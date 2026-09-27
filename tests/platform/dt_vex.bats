#!/usr/bin/env bats
# DHI OpenVEX applied in Dependency-Track, live: every `not_affected` statement of the DHI base of the golden
# python image that matches a Dependency-Track finding of its project shows as NOT_AFFECTED with the vendor
# justification. DHI_USERNAME and DHI_TOKEN come from the environment; the token only goes through stdin.

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

@test "DHI not_affected statements show as NOT_AFFECTED with vendor justification" {
  [ -n "${DHI_USERNAME:-}" ] || fail "DHI_USERNAME is not set in the environment"
  [ -n "${DHI_TOKEN:-}" ] || fail "DHI_TOKEN is not set in the environment"
  resolve_golden_run
  digest="$(golden_ghcr_digest "$GOLDEN_NAME")"
  golden_ref="$GHCR_GOLDEN/$GOLDEN_NAME@$digest"
  image="$GOLDEN_PROJECT/$GOLDEN_NAME"
  tag="sha-$GOLDEN_SHA"
  resolve_dhi_base "$golden_ref"

  # dhi.io serves its attestations only to an authenticated client: a throwaway Docker config, token on stdin.
  export DOCKER_CONFIG="$BATS_TEST_TMPDIR/docker"
  (umask 077 && mkdir -p "$DOCKER_CONFIG")
  printf '%s' "$DHI_TOKEN" | crane auth login dhi.io -u "$DHI_USERNAME" --password-stdin >/dev/null 2>&1 ||
    fail "crane auth login dhi.io failed for DHI_USERNAME"
  openvex="$BATS_TEST_TMPDIR/dhi-openvex.json"
  fetch_dhi_openvex "$golden_ref" "$openvex"

  # One entry per not_affected statement: ids, product purls, expected DT justification(s) and the vendor
  # texts the analysis details must carry.
  expected="$BATS_TEST_TMPDIR/expected.json"
  jq "$PURL_JQ"' .author as $author | [.statements[] | select(.status == "not_affected") | {
      ids: ([.vulnerability.name] + (.vulnerability.aliases // [])),
      products: ([.products[]? | (.subcomponents // [.])[] | .["@id"] // empty] | unique),
      justification: ({
        component_not_present: ["CODE_NOT_PRESENT"],
        vulnerable_code_not_present: ["CODE_NOT_PRESENT"],
        vulnerable_code_not_in_execute_path: ["CODE_NOT_REACHABLE"],
        inline_mitigations_already_exist: ["PROTECTED_BY_MITIGATING_CONTROL"]
      }[.justification // ""] // ["NOT_SET", null]),
      texts: ([$author, .justification, .status_notes, .impact_statement] | map(select(. != null and . != "")))
    }]' "$openvex" >"$expected"
  jq -e 'length > 0' "$expected" >/dev/null || fail "the DHI OpenVEX of $DHI_BASE_REPO@$DHI_BASE_DIGEST has no not_affected statement"

  replicate "$GOLDEN_REPLICATION"

  deadline=$((SECONDS + VEX_TIMEOUT_SECONDS))
  while :; do
    uuid="$(dt_project_uuid "$image" "$tag")" || return 1
    offenders=""
    if [ -z "$uuid" ]; then
      diagnosis="no Dependency-Track project '$image' version '$tag'"
    else
      dt_findings "$uuid" "$BATS_TEST_TMPDIR/findings.json" || return 1
      # DT findings a statement covers: same vulnerability (DT id, or one of either side's aliases) on a
      # component one of its products covers.
      jq -n "$PURL_JQ"' input as $expected | input as $findings | [
          $findings[] as $f
          | ([$f.vulnerability.vulnId] + [$f.vulnerability.aliases[]? | .[]? | strings]) as $finding_ids
          | ($f.component.purl // "") as $component
          | $expected[] | select(any(.ids[]; . as $id | any($finding_ids[]; . == $id))
              and $component != "" and any(.products[]; purl_covers(.; $component)))
          | {vuln: $f.vulnerability.vulnId, vuln_uuid: $f.vulnerability.uuid, component: $component,
             component_uuid: $f.component.uuid, justification, texts}
        ] | unique_by([.vuln_uuid, .component_uuid])' "$expected" "$BATS_TEST_TMPDIR/findings.json" \
        >"$BATS_TEST_TMPDIR/covered.json"

      if [ "$(jq length "$BATS_TEST_TMPDIR/covered.json")" -eq 0 ]; then
        diagnosis="no finding of project '$image' version '$tag' ($(jq length "$BATS_TEST_TMPDIR/findings.json") finding(s)) matches one of the $(jq length "$expected") DHI not_affected statements: the check would be vacuous"
      else
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
        [ -n "$offenders" ] || return 0
        diagnosis="$(jq length "$BATS_TEST_TMPDIR/covered.json") finding(s) covered by DHI not_affected statements, not applied as expected: $offenders"
      fi
    fi
    [ "$SECONDS" -lt "$deadline" ] || fail "${VEX_TIMEOUT_SECONDS}s after the replication: $diagnosis"
    sleep 15
  done
}
