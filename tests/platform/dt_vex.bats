#!/usr/bin/env bats
# DHI OpenVEX forwarded to Dependency-Track, live: dt-bridge converts the not_affected statements of the DHI base
# of the golden python image to a CycloneDX VEX on its attested SBOM components, and Dependency-Track processes it.
# DHI_USERNAME and DHI_TOKEN come from the environment; the token only goes through stdin.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
load ../supply-chain/golden
load ../supply-chain/apps
load dt

GOLDEN_NAME=python
OPENVEX_PREDICATE_TYPE=https://openvex.dev/ns/v0.2.0
INTOTO_ARTIFACT_TYPE=application/vnd.in-toto+json
VEX_TIMEOUT_SECONDS=600

setup_file() {
  dt_setup_file
}

setup() {
  dt_setup
}

# Sets DHI_BASE_REPO (e.g. dhi.io/python) and DHI_BASE_DIGEST: the single dhi.io dependency of the verified
# SLSA provenance of golden image $1 (a digest reference).
resolve_dhi_base() {
  local ref="$1" provenance="$BATS_TEST_TMPDIR/provenance.json" bases base_uri base_hex
  golden_cosign_args
  cosign verify-attestation "${GOLDEN_COSIGN[@]}" --type slsaprovenance1 "$ref" >"$provenance" 2>/dev/null ||
    fail "SLSA provenance of $ref not verified against $(golden_identity)"
  mapfile -t bases < <(attestation_statements "$provenance" | jq -r '[.[].predicate.buildDefinition.resolvedDependencies[]?
      | select((.uri // "") | startswith("oci://dhi.io/")) | "\(.uri)|\(.digest.sha256 // "")"] | unique[]')
  [ "${#bases[@]}" -eq 1 ] || fail "SLSA provenance of $ref records ${#bases[@]} dhi.io base(s), expected one: ${bases[*]}"
  IFS='|' read -r base_uri base_hex <<<"${bases[0]}"
  [[ "$base_hex" =~ ^[0-9a-f]{64}$ ]] || fail "dhi.io base $base_uri has no sha256 digest in the provenance of $ref"
  DHI_BASE_REPO="${base_uri#oci://}"
  DHI_BASE_REPO="${DHI_BASE_REPO%%@*}"
  if [[ "${DHI_BASE_REPO##*/}" == *:* ]]; then
    DHI_BASE_REPO="${DHI_BASE_REPO%:*}"
  fi
  DHI_BASE_DIGEST="sha256:$base_hex"
}

# Writes to file $2 the most recent DHI OpenVEX document attested for the platform manifest of the DHI base
# matching the platform of golden image $1. DHI attaches its attestations as OCI referrers of each platform
# manifest (in-toto statements, predicate type in the `in-toto.io/predicate-type` annotation).
fetch_dhi_openvex() {
  local golden_ref="$1" out="$2" platform manifest platform_digest referrers digest layer statement best=""
  platform="$(crane config "$golden_ref" | jq -r '"\(.os)/\(.architecture)"')"
  [[ "$platform" == */* && "$platform" != null/* ]] || fail "cannot read the platform of $golden_ref"

  manifest="$BATS_TEST_TMPDIR/dhi-manifest.json"
  crane manifest "$DHI_BASE_REPO@$DHI_BASE_DIGEST" >"$manifest" 2>/dev/null ||
    fail "cannot read $DHI_BASE_REPO@$DHI_BASE_DIGEST with the DHI credentials"
  if jq -e '.manifests' "$manifest" >/dev/null; then
    platform_digest="$(jq -r --arg p "$platform" \
      '[.manifests[] | select("\(.platform.os)/\(.platform.architecture)" == $p) | .digest][0] // ""' "$manifest")"
    [ -n "$platform_digest" ] || fail "$DHI_BASE_REPO@$DHI_BASE_DIGEST has no $platform manifest"
  else
    platform_digest="$DHI_BASE_DIGEST"
  fi

  referrers="$BATS_TEST_TMPDIR/dhi-referrers.json"
  crane auth token -H "$DHI_BASE_REPO" 2>/dev/null |
    curl -sSf -H @- -H 'Accept: application/vnd.oci.image.index.v1+json' -o "$referrers" \
      "https://${DHI_BASE_REPO%%/*}/v2/${DHI_BASE_REPO#*/}/referrers/$platform_digest?artifactType=$(jq -rn --arg t "$INTOTO_ARTIFACT_TYPE" '$t | @uri')" ||
    fail "cannot list the referrers of $DHI_BASE_REPO@$platform_digest"

  for digest in $(jq -r --arg t "$OPENVEX_PREDICATE_TYPE" \
    '.manifests[]? | select(.annotations["in-toto.io/predicate-type"] == $t) | .digest' "$referrers"); do
    layer="$(crane manifest "$DHI_BASE_REPO@$digest" | jq -r '.layers[0].digest')"
    statement="$BATS_TEST_TMPDIR/openvex-${digest#sha256:}.json"
    crane blob "$DHI_BASE_REPO@$layer" >"$statement" || fail "cannot fetch the OpenVEX attestation $DHI_BASE_REPO@$digest"
    jq -e --arg t "$OPENVEX_PREDICATE_TYPE" '.predicateType == $t and (.predicate.statements | type == "array")' \
      "$statement" >/dev/null || fail "$DHI_BASE_REPO@$digest is not an in-toto statement carrying an OpenVEX document"
    if [ -z "$best" ] || jq -e -n --slurpfile a "$statement" --slurpfile b "$best" \
      '($a[0].predicate | .last_updated // .timestamp) > ($b[0].predicate | .last_updated // .timestamp)' >/dev/null; then
      best="$statement"
    fi
  done
  [ -n "$best" ] || fail "no OpenVEX attestation among the referrers of $DHI_BASE_REPO@$platform_digest"
  jq '.predicate' "$best" >"$out"
}

# Writes to file $3 one entry per not_affected statement of the OpenVEX document in file $1: its ids, product
# purls, CycloneDX and DT justifications (mapping of the M6 interface), the vendor texts the analysis detail must
# carry, the bom-refs of the attested components (file $2) it covers, and whether another statement gives one
# of its ids another status (then a later statement may override it and completeness is not required).
not_affected_statements() {
  jq -n "$VEX_JQ"' input as $doc | input as $attested
    | [$doc.statements[] | select(.status != "not_affected") | .vulnerability.name] as $contested
    | $doc.author as $author
    | [$doc.statements[] | select(.status == "not_affected") | {
        ids: ([.vulnerability.name] + (.vulnerability.aliases // [])),
        products: ([.products[]? | (.subcomponents // [.])[] | .["@id"] // empty] | unique),
        label: (.justification // null),
        cdx: ({
          component_not_present: "code_not_present",
          vulnerable_code_not_present: "code_not_present",
          vulnerable_code_not_in_execute_path: "code_not_reachable",
          inline_mitigations_already_exist: "protected_by_mitigating_control"
        }[.justification // ""]),
        dt: ({
          component_not_present: ["CODE_NOT_PRESENT"],
          vulnerable_code_not_present: ["CODE_NOT_PRESENT"],
          vulnerable_code_not_in_execute_path: ["CODE_NOT_REACHABLE"],
          inline_mitigations_already_exist: ["PROTECTED_BY_MITIGATING_CONTROL"]
        }[.justification // ""] // ["NOT_SET", null]),
        texts: ([$author, .justification, .status_notes, .impact_statement] | map(select(. != null and . != "")))
      }
      | ([.products[] | purl_parts]) as $parts
      | . + {refs: [$attested[] | . as $c | select(any($parts[]; parts_cover(.; $c.parts))) | .ref] | unique}
      | . + {contested: any(.ids[]; IN($contested[]))}]' "$1" "$2" >"$3"
}

# Problems of the CycloneDX VEX in file $1 against the statements (file $2), the attested components (file $3),
# the normalised component purls of the DT project (file $4, a JSON array) and the DT findings (file $5), one
# per line; nothing when the VEX is the conversion the M6 interface describes.
vex_problems() {
  jq -r -n "$VEX_JQ"' input as $vex | input as $statements | input as $attested | input as $dt_purls
    | input as $findings
    | ([$findings[] | {key: .vulnerability.vulnId, value: [.vulnerability.aliases[]? | .[]? | strings]}]
        | group_by(.key) | map({key: .[0].key, value: (map(.value[]) | unique)}) | from_entries) as $dt_aliases
    | ($attested | map({key: .ref, value: .norm}) | from_entries) as $attested_by_ref
    | ($vex.components // []) as $components
    | [$components[] | .["bom-ref"] // empty] as $vex_refs
    | ($vex.vulnerabilities // []) as $vulns
    | def vuln_ids: [.id] + [.references[]?.id] + ($dt_aliases[.id] // []);
      def mismatch($s): [
        (if .analysis.state != "not_affected" then "state \(.analysis.state // "none")" else empty end),
        (if .analysis.justification != $s.cdx
          then "justification \(.analysis.justification // "none") instead of \($s.cdx // "none")" else empty end),
        ($s.texts[] as $t | if ((.analysis.detail // "") | index($t)) == null
          then "detail lacks \($t | .[0:60] | @json)" else empty end)
      ] | join(", ");
    [
      (if $vex.bomFormat != "CycloneDX" then "bomFormat is \($vex.bomFormat | @json)" else empty end),
      (if ($vex.specVersion | IN("1.4", "1.5", "1.6", "1.7")) | not
        then "specVersion is \($vex.specVersion | @json)" else empty end),
      (if ($components | length) == 0 then "no component" else empty end),
      ($components[] | (.["bom-ref"] // "") as $ref | (.purl // "") as $purl
        | if $ref == "" or $purl == "" then "component without bom-ref or purl: \(tojson | .[0:120])"
          elif $attested_by_ref[$ref] == null then "component \($ref) is not a component of the attested SBOM"
          elif $attested_by_ref[$ref] != ($purl | purl_norm)
            then "component \($ref) has purl \($purl), the attested SBOM \($attested_by_ref[$ref])"
          elif (($purl | purl_norm) | IN($dt_purls[])) | not
            then "component \($purl) is not a component of the Dependency-Track project"
          else empty end),
      (if ($vulns | length) == 0 then "no vulnerability" else empty end),
      ($vulns[] | . as $v | vuln_ids as $ids | [.affects[]?.ref] as $refs
        | [$statements[] | select(any(.ids[]; IN($ids[])))] as $same
        | [$same[] | . as $s | select(all($refs[]; IN($s.refs[])))] as $covering
        | "vulnerability \(.id): " + (
            if ($refs | length) == 0 then "affects no component"
            elif any($refs[]; IN($vex_refs[]) | not)
              then "affects \([$refs[] | select(IN($vex_refs[]) | not)][0]), not a component of the VEX"
            elif ($same | length) == 0 then "matches no DHI not_affected statement"
            elif ($covering | length) == 0
              then "affects components no single DHI statement for it covers: \($refs | join(" "))"
            elif any($covering[]; . as $s | $v | mismatch($s) == "") then ""
            else $v | mismatch($covering[0]) end)
        | select(endswith(": ") | not)),
      ($statements[] | select((.contested | not) and (.refs | length) > 0) | . as $s
        | [$vulns[] | select(any(vuln_ids[]; IN($s.ids[]))) | .affects[]?.ref] as $converted
        | [$s.refs[] | select(IN($converted[]) | not)] as $missing
        | if ($missing | length) > 0
          then "statement \($s.ids[0]) not converted for \($missing | length) covered component(s), e.g. \($missing[0])"
          else empty end)
    ] | unique[]' "$1" "$2" "$3" "$4" "$5"
}

@test "dt-bridge converts DHI not_affected statements to a CycloneDX VEX that Dependency-Track accepts" {
  [ -n "${DHI_USERNAME:-}" ] || fail "DHI_USERNAME is not set in the environment"
  [ -n "${DHI_TOKEN:-}" ] || fail "DHI_TOKEN is not set in the environment"
  resolve_golden_run
  digest="$(golden_ghcr_digest "$GOLDEN_NAME")"
  golden_ref="$GHCR_GOLDEN/$GOLDEN_NAME@$digest"
  image="$GOLDEN_PROJECT/$GOLDEN_NAME"
  tag="sha-$GOLDEN_SHA"
  resolve_dhi_base "$golden_ref"

  golden_cosign_args
  cosign verify-attestation "${GOLDEN_COSIGN[@]}" --type cyclonedx "$golden_ref" \
    >"$BATS_TEST_TMPDIR/attestation-cyclonedx.json" 2>/dev/null ||
    fail "CycloneDX attestation of $golden_ref not verified against $(golden_identity)"
  attestation_statements "$BATS_TEST_TMPDIR/attestation-cyclonedx.json" | jq '[.[] | .predicate]' \
    >"$BATS_TEST_TMPDIR/attested-sboms.json"
  jq -e 'length == 1' "$BATS_TEST_TMPDIR/attested-sboms.json" >/dev/null ||
    fail "expected one CycloneDX attestation on $golden_ref, found $(jq length "$BATS_TEST_TMPDIR/attested-sboms.json")"
  jq '.[0]' "$BATS_TEST_TMPDIR/attested-sboms.json" >"$BATS_TEST_TMPDIR/sbom.json"
  attested="$BATS_TEST_TMPDIR/attested.json"
  attested_components "$BATS_TEST_TMPDIR/sbom.json" "$attested"

  # dhi.io serves its attestations only to an authenticated client: a throwaway Docker config, token on stdin.
  export DOCKER_CONFIG="$BATS_TEST_TMPDIR/docker"
  (umask 077 && mkdir -p "$DOCKER_CONFIG")
  printf '%s' "$DHI_TOKEN" | crane auth login dhi.io -u "$DHI_USERNAME" --password-stdin >/dev/null 2>&1 ||
    fail "crane auth login dhi.io failed for DHI_USERNAME"
  openvex="$BATS_TEST_TMPDIR/dhi-openvex.json"
  fetch_dhi_openvex "$golden_ref" "$openvex"

  statements="$BATS_TEST_TMPDIR/statements.json"
  not_affected_statements "$openvex" "$attested" "$statements"
  jq -e 'any(.[]; (.refs | length) > 0)' "$statements" >/dev/null ||
    fail "no not_affected statement of the DHI OpenVEX of $DHI_BASE_REPO@$DHI_BASE_DIGEST covers a component of the attested SBOM ($(jq length "$statements") statement(s)): the check would be vacuous"

  since="$(date -u -d "@$(($(date +%s) - LOG_MARGIN_SECONDS))" +%Y-%m-%dT%H:%M:%SZ)"
  replicate "$GOLDEN_REPLICATION"

  deadline=$((SECONDS + VEX_TIMEOUT_SECONDS))
  while :; do
    uuid="$(dt_project_uuid "$image" "$tag")" || return 1
    entries="$BATS_TEST_TMPDIR/entries.json"
    dt_bridge_entries "$image" "$tag" "$since" "$entries" || return 1
    uploaded="$(jq -c '[.[] | select(.message == "DHI VEX uploaded")] | last // empty' "$entries")"
    if [ -z "$uuid" ]; then
      diagnosis="no Dependency-Track project '$image' version '$tag'"
    elif [ -z "$uploaded" ]; then
      diagnosis="dt-bridge logged no 'DHI VEX uploaded' for $image:$tag since the replication (its messages about it: $(
        jq -r '[.[] | .message + (if .error then " (\(.error))" else "" end)] | unique | join("; ")' "$entries"))"
    else
      token="$(jq -r '.token // ""' <<<"$uploaded")"
      [[ "$token" =~ $UUID_RE ]] || fail "the 'DHI VEX uploaded' entry of $image:$tag carries no Dependency-Track token: $(jq -c 'del(.vex)' <<<"$uploaded")"
      bom_token="$(jq -r '[.[] | select(.message == "SBOM uploaded")] | last | .token // ""' "$entries")"
      [[ "$bom_token" =~ $UUID_RE ]] || fail "dt-bridge logged no 'SBOM uploaded' entry with a token for $image:$tag since the replication"
      [ "$token" != "$bom_token" ] || fail "the VEX token of $image:$tag is the BOM upload token $bom_token"
      [ "$(jq -r '.project_uuid // ""' <<<"$uploaded")" = "$uuid" ] ||
        fail "the VEX of $image:$tag was accepted for project $(jq -r '.project_uuid // "none"' <<<"$uploaded"), not '$image' version '$tag' ($uuid)"
      jq '.vex' <<<"$uploaded" >"$BATS_TEST_TMPDIR/vex.json"
      jq -e 'type == "object"' "$BATS_TEST_TMPDIR/vex.json" >/dev/null ||
        fail "the 'DHI VEX uploaded' entry of $image:$tag carries no VEX document"

      dt_components "$uuid" "$BATS_TEST_TMPDIR/dt-components.json" || return 1
      jq "$PURL_JQ"' [.[] | .purl // empty | purl_norm] | unique' "$BATS_TEST_TMPDIR/dt-components.json" \
        >"$BATS_TEST_TMPDIR/dt-purls.json"
      dt_findings "$uuid" "$BATS_TEST_TMPDIR/findings.json" || return 1
      problems="$(vex_problems "$BATS_TEST_TMPDIR/vex.json" "$statements" "$attested" \
        "$BATS_TEST_TMPDIR/dt-purls.json" "$BATS_TEST_TMPDIR/findings.json")"
      [ -z "$problems" ] ||
        fail "the VEX dt-bridge uploaded for $image:$tag is not the conversion of the DHI OpenVEX: $(head -n 10 <<<"$problems" | paste -sd ';' -)"

      dt_get "/v1/event/token/$token" || return 1
      [ "$HTTP_CODE" = 200 ] || fail "cannot read Dependency-Track token $token (HTTP $HTTP_CODE)"
      status="$(jq -r '.status // "none"' "$HTTP_BODY")"
      [ "$status" != FAILED ] || fail "Dependency-Track failed to process the VEX of $image:$tag (token $token)"

      # Once Dependency-Track lists findings a DHI statement covers (same vulnerability by DT id or alias, on
      # a component a product covers), each must carry the vendor analysis: the full criterion 17.
      jq -n "$VEX_JQ"' input as $statements | input as $findings | [
          $findings[] as $f
          | ([$f.vulnerability.vulnId] + [$f.vulnerability.aliases[]? | .[]? | strings]) as $finding_ids
          | ($f.component.purl // "") as $component
          | $statements[] | select(any(.ids[]; IN($finding_ids[]))
              and $component != "" and any(.products[]; purl_covers(.; $component)))
          | {vuln: $f.vulnerability.vulnId, vuln_uuid: $f.vulnerability.uuid, component: $component,
             component_uuid: $f.component.uuid, justification: .dt, texts}
        ] | unique_by([.vuln_uuid, .component_uuid])' "$statements" "$BATS_TEST_TMPDIR/findings.json" \
        >"$BATS_TEST_TMPDIR/covered.json"
      offenders=""
      while read -r covered; do
        dt_get /v1/analysis -G --data-urlencode "project=$uuid" \
          --data-urlencode "component=$(jq -r .component_uuid <<<"$covered")" \
          --data-urlencode "vulnerability=$(jq -r .vuln_uuid <<<"$covered")" || return 1
        label="$(jq -r '"\(.vuln) on \(.component)"' <<<"$covered")"
        if [ "$HTTP_CODE" != 200 ]; then
          offenders+="$label: no analysis (HTTP $HTTP_CODE); "
          continue
        fi
        problem="$(jq -r --argjson c "$covered" '
          [ (if .analysisState != "NOT_AFFECTED" then "state \(.analysisState // "none")" else empty end),
            (.analysisJustification as $j | if any($c.justification[]; . == $j) | not
              then "justification \(.analysisJustification // "none") instead of \($c.justification | map(. // "none") | join(" or "))"
              else empty end),
            ($c.texts[] as $t | if ((.analysisDetails // "") | index($t)) == null
              then "details lack \($t | .[0:60] | @json)" else empty end)
          ] | join(", ")' "$HTTP_BODY")"
        [ -z "$problem" ] || offenders+="$label: $problem; "
      done < <(jq -c '.[]' "$BATS_TEST_TMPDIR/covered.json")

      if [ "$status" != COMPLETED ]; then
        diagnosis="Dependency-Track has not completed the VEX of $image:$tag (token $token, status $status)"
      elif [ -n "$offenders" ]; then
        diagnosis="$(jq length "$BATS_TEST_TMPDIR/covered.json") finding(s) covered by DHI not_affected statements, not applied as expected: $offenders"
      else
        echo "# VEX token $token COMPLETED: $(jq '.vulnerabilities | length' "$BATS_TEST_TMPDIR/vex.json") vulnerabilities on $(jq '.components | length' "$BATS_TEST_TMPDIR/vex.json") components; $(jq length "$BATS_TEST_TMPDIR/covered.json") DT finding(s) covered by the DHI statements" >&3
        return 0
      fi
    fi
    [ "$SECONDS" -lt "$deadline" ] || fail "${VEX_TIMEOUT_SECONDS}s after the replication: $diagnosis"
    sleep 15
  done
}
