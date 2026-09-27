#!/usr/bin/env bats
# Kubescape runtime OpenVEX forwarded to Dependency-Track, live: once Kubescape has observed a restarted
# hello-java container, dt-bridge converts the runtime not_affected statements of that container to a CycloneDX
# VEX on the attested SBOM components of the running image, and Dependency-Track processes it.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
load ../supply-chain/golden
load ../supply-chain/apps
load dt

KUBESCAPE_NAMESPACE=kubescape
KUBESCAPE_APPLICATION=kubescape
KUBESCAPE_APISERVICE=v1beta1.spdx.softwarecomposition.kubescape.io
KUBESCAPE_GROUP=spdx.softwarecomposition.kubescape.io
VEX_RESOURCE="openvulnerabilityexchangecontainers.$KUBESCAPE_GROUP"
INSTANCE_ID_ANNOTATION=kubescape.io/instance-id
WORKLOAD_NAMESPACE=hello-java
WORKLOAD_DEPLOYMENT=hello-java
WORKLOAD_CONTAINER=hello-java
DT_BRIDGE_SUBJECT=system:serviceaccount:dt-bridge:dt-bridge
ROLLOUT_TIMEOUT_SECONDS=300
# Learning period (2 min by default), then the kubevuln scan (the first one downloads the Grype database),
# dt-bridge's collection and Dependency-Track's processing.
RUNTIME_VEX_TIMEOUT_SECONDS=1200

setup_file() {
  dt_setup_file
}

setup() {
  dt_setup
}

# jq definitions over VEX_JQ: same_package is the package a Kubescape subcomponent names (same type, namespace,
# name and version), narrower than parts_cover, which also follows the `upstream` qualifier.
RUNTIME_JQ="$VEX_JQ"'
  def same_package($p; $c): $p.namespace == $c.namespace and $p.name == $c.name
    and ($p.version == null or $p.version == $c.version);'

assert_kubescape_serving() {
  local state available
  state="$(kubectl -n argocd get application "$KUBESCAPE_APPLICATION" \
    -o jsonpath='{.status.sync.status} {.status.health.status}' 2>&1)" ||
    fail "Argo CD Application $KUBESCAPE_APPLICATION not found: $state"
  [ "$state" = "Synced Healthy" ] || fail "Argo CD Application $KUBESCAPE_APPLICATION is '$state', not 'Synced Healthy'"
  available="$(kubectl get apiservice "$KUBESCAPE_APISERVICE" \
    -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' 2>&1)" ||
    fail "APIService $KUBESCAPE_APISERVICE (Kubescape storage) not found: $available"
  [ "$available" = True ] || fail "APIService $KUBESCAPE_APISERVICE is not Available ($available)"
}

# Restarts the workload so Kubescape observes its container from the start, then sets RS (the new ReplicaSet),
# IMAGE_ID (the running container's image ID) and INSTANCE_ID (Kubescape's id of that container instance).
restart_workload() {
  local revision err="$BATS_TEST_TMPDIR/rollout.err"
  kubectl -n "$WORKLOAD_NAMESPACE" rollout restart "deployment/$WORKLOAD_DEPLOYMENT" >/dev/null 2>"$err" ||
    fail "cannot restart deployment $WORKLOAD_NAMESPACE/$WORKLOAD_DEPLOYMENT: $(tail -n 3 "$err")"
  kubectl -n "$WORKLOAD_NAMESPACE" rollout status "deployment/$WORKLOAD_DEPLOYMENT" \
    --timeout="${ROLLOUT_TIMEOUT_SECONDS}s" >/dev/null 2>"$err" ||
    fail "deployment $WORKLOAD_NAMESPACE/$WORKLOAD_DEPLOYMENT not rolled out after restart: $(tail -n 3 "$err")"

  revision="$(kubectl -n "$WORKLOAD_NAMESPACE" get deployment "$WORKLOAD_DEPLOYMENT" \
    -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}')"
  RS="$(kubectl -n "$WORKLOAD_NAMESPACE" get replicasets -o json | jq -r --arg d "$WORKLOAD_DEPLOYMENT" --arg r "$revision" \
    '[.items[] | select(any(.metadata.ownerReferences[]?; .kind == "Deployment" and .name == $d))
      | select(.metadata.annotations["deployment.kubernetes.io/revision"] == $r) | .metadata.name][0] // ""')"
  [ -n "$RS" ] || fail "no ReplicaSet of revision $revision for deployment $WORKLOAD_NAMESPACE/$WORKLOAD_DEPLOYMENT"
  IMAGE_ID="$(kubectl -n "$WORKLOAD_NAMESPACE" get pods -o json | jq -r --arg rs "$RS" --arg c "$WORKLOAD_CONTAINER" \
    '[.items[] | select(.metadata.deletionTimestamp == null)
      | select(any(.metadata.ownerReferences[]?; .kind == "ReplicaSet" and .name == $rs))
      | .status.containerStatuses[]? | select(.name == $c and .state.running != null) | .imageID][0] // ""')"
  [ -n "$IMAGE_ID" ] || fail "no running $WORKLOAD_CONTAINER container in ReplicaSet $WORKLOAD_NAMESPACE/$RS"
  INSTANCE_ID="apiVersion-apps/v1/namespace-$WORKLOAD_NAMESPACE/kind-ReplicaSet/name-$RS/containerName-$WORKLOAD_CONTAINER"
}

# Sets IMAGE (Harbor `<project>/<repository>`), DIGEST and TAG (the one image tag Harbor holds for DIGEST)
# from the image ID $1 of a container running a Harbor `apps` image.
resolve_harbor_image() {
  local ref="${1#docker-pullable://}" path tags
  ref="${ref#docker://}"
  [[ "$ref" == "$HARBOR_HOST/$APPS_PROJECT/"*@sha256:* ]] ||
    fail "container image ID '$1' is not a Harbor $APPS_PROJECT digest reference"
  path="${ref#"$HARBOR_HOST/"}"
  IMAGE="${path%%@*}"
  DIGEST="${ref##*@}"
  harbor_admin GET "/projects/$APPS_PROJECT/repositories/${IMAGE#"$APPS_PROJECT/"}/artifacts/$DIGEST?with_tag=true"
  [ "$HTTP_CODE" = 200 ] || fail "cannot read Harbor artifact $IMAGE@$DIGEST (HTTP $HTTP_CODE)"
  mapfile -t tags < <(jq -r '.tags[]?.name | select(startswith("sha256-") | not)' "$HTTP_BODY")
  [ "${#tags[@]}" -eq 1 ] || fail "Harbor artifact $IMAGE@$DIGEST has ${#tags[@]} image tag(s), expected one: ${tags[*]}"
  TAG="${tags[0]}"
}

# Writes to file $3 one entry per statement of the Kubescape OpenVEX document in file $1: its ids, status, product
# purls (the subcomponents: the packages), CycloneDX and DT justifications (M6 mapping), the texts the analysis
# detail must carry, the bom-refs of the attested components (file $2) it covers (name or upstream, the
# converter's rule) and those whose own package it names.
runtime_statements() {
  jq -n "$RUNTIME_JQ"' input as $doc | input as $attested
    | $doc.author as $author
    | [$doc.statements[] | {
        ids: ([.vulnerability.name] + (.vulnerability.aliases // []) | map(select(type == "string" and . != ""))),
        status,
        products: ([.products[]? | (.subcomponents // [.])[] | .["@id"] // empty] | unique),
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
      | . + {covers: [$attested[] | . as $c | select(any($parts[]; parts_cover(.; $c.parts))) | .ref] | unique,
             names: [$attested[] | . as $c | select(any($parts[]; same_package(.; $c.parts))) | .ref] | unique}]' \
    "$1" "$2" >"$3"
}

# (statement index, bom-ref) pairs a conversion must emit, as a JSON array on stdout: the attested components a
# not_affected statement covers, unless a statement of the same vulnerability with another status covers them.
required_pairs() {
  jq -c '. as $all | [$all[] | select(.status != "not_affected")] as $other
    | [$all | to_entries[] | select(.value.status == "not_affected") | .key as $i | .value as $s
        | $s.covers[] as $r
        | select(any($other[]; any(.ids[]; IN($s.ids[])) and any(.covers[]; . == $r)) | not)
        | {statement: $i, ref: $r}]' "$1"
}

# Problems of the CycloneDX VEX in file $1 against the Kubescape statements (file $2), the attested components
# (file $3), the normalised component purls of the DT project (file $4, a JSON array) and the DT findings (file
# $5), one per line; nothing when the VEX is the conversion of the runtime not_affected statements.
runtime_vex_problems() {
  jq -r -n "$RUNTIME_JQ"' input as $vex | input as $statements | input as $attested | input as $dt_purls
    | input as $findings
    | ([$findings[] | {key: .vulnerability.vulnId, value: [.vulnerability.aliases[]? | .[]? | strings]}]
        | group_by(.key) | map({key: .[0].key, value: (map(.value[]) | unique)}) | from_entries) as $dt_aliases
    | ($attested | map({key: .ref, value: .norm}) | from_entries) as $attested_by_ref
    | ($vex.components // []) as $components
    | [$components[] | .["bom-ref"] // empty] as $vex_refs
    | ($vex.vulnerabilities // []) as $vulns
    | [$statements[] | select(.status == "not_affected")] as $not_affected
    | [$statements[] | select(.status != "not_affected")] as $other
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
        | if ($refs | length) == 0 then "vulnerability \($v.id) affects no component" else
          ($refs[] as $r
            | [$not_affected[] | . as $s | select(any($s.ids[]; IN($ids[])) and any($s.covers[]; . == $r))]
              as $covering
            | [$other[] | . as $s | select(any($s.ids[]; IN($ids[])) and any($s.names[]; . == $r))] as $runtime
            | "vulnerability \($v.id) on \($r): " + (
                if ($r | IN($vex_refs[])) | not then "not a component of the VEX"
                elif ($runtime | length) > 0
                  then "Kubescape reports this package \($runtime[0].status) at runtime, not not_affected"
                elif ($covering | length) == 0 then "no Kubescape not_affected statement covers it"
                elif any($covering[]; . as $s | $v | mismatch($s) == "") then ""
                else $v | mismatch($covering[0]) end)
            | select(endswith(": ") | not)) end),
      ($statements | to_entries[] | select(.value.status == "not_affected") | .key as $i | .value as $s
        | [$s.covers[] as $r
            | select(any($other[]; any(.ids[]; IN($s.ids[])) and any(.covers[]; . == $r)) | not) | $r] as $required
        | [$vulns[] | select(any(vuln_ids[]; IN($s.ids[]))) | .affects[]?.ref] as $converted
        | [$required[] | select(IN($converted[]) | not)] as $missing
        | if ($missing | length) > 0
          then "statement \($s.ids[0]) not converted for \($missing | length) covered component(s), e.g. \($missing[0])"
          else empty end)
    ] | unique[]' "$1" "$2" "$3" "$4" "$5"
}

# The Kubescape VEX document of container instance $1 (JSON object, spec included) on stdout, or nothing.
instance_vex_document() {
  local list="$BATS_TEST_TMPDIR/vex-documents.json"
  kubectl -n "$KUBESCAPE_NAMESPACE" get "$VEX_RESOURCE" -o json >"$list" 2>"$list.err" || {
    echo '{"error": true}'
    return 0
  }
  jq -c --arg key "$INSTANCE_ID_ANNOTATION" --arg id "$1" \
    '[.items[] | select(.metadata.annotations[$key] == $id)] | last // empty' "$list"
}

@test "Kubescape runtime OpenVEX is applied in Dependency-Track" {
  assert_kubescape_serving

  since="$(date -u -d "@$(($(date +%s) - LOG_MARGIN_SECONDS))" +%Y-%m-%dT%H:%M:%SZ)"
  restart_workload
  resolve_harbor_image "$IMAGE_ID"
  [[ "$TAG" =~ ^sha-([0-9a-f]{40})$ ]] || fail "Harbor tag '$TAG' of $IMAGE@$DIGEST is not sha-<commit>"
  APP_SHA="${BASH_REMATCH[1]}"
  APP_REF="${GOLDEN_REF:-refs/heads/$(git -C "$REPO_ROOT" symbolic-ref --quiet --short HEAD)}"

  app_cosign_args
  cosign verify-attestation "${APP_COSIGN[@]}" --registry-cacert "$PLATFORM_CA" --type cyclonedx \
    "$HARBOR_HOST/$IMAGE@$DIGEST" >"$BATS_TEST_TMPDIR/attestation-cyclonedx.json" 2>"$BATS_TEST_TMPDIR/cosign.err" ||
    fail "CycloneDX attestation of $HARBOR_HOST/$IMAGE@$DIGEST not verified: $(tail -n 5 "$BATS_TEST_TMPDIR/cosign.err")"
  attestation_statements "$BATS_TEST_TMPDIR/attestation-cyclonedx.json" | jq '[.[] | .predicate]' \
    >"$BATS_TEST_TMPDIR/attested-sboms.json"
  jq -e 'length == 1' "$BATS_TEST_TMPDIR/attested-sboms.json" >/dev/null ||
    fail "expected one CycloneDX attestation on $IMAGE@$DIGEST, found $(jq length "$BATS_TEST_TMPDIR/attested-sboms.json")"
  jq '.[0]' "$BATS_TEST_TMPDIR/attested-sboms.json" >"$BATS_TEST_TMPDIR/sbom.json"
  attested="$BATS_TEST_TMPDIR/attested.json"
  attested_components "$BATS_TEST_TMPDIR/sbom.json" "$attested"

  statements="$BATS_TEST_TMPDIR/statements.json"
  deadline=$((SECONDS + RUNTIME_VEX_TIMEOUT_SECONDS))
  while :; do
    document="$(instance_vex_document "$INSTANCE_ID")"
    uuid="$(dt_project_uuid "$IMAGE" "$TAG")" || return 1
    if [ "$document" = '{"error": true}' ]; then
      diagnosis="cannot list $VEX_RESOURCE in $KUBESCAPE_NAMESPACE: $(tail -n 2 "$BATS_TEST_TMPDIR/vex-documents.json.err")"
    elif [ -z "$document" ]; then
      diagnosis="Kubescape published no VEX document for container instance $INSTANCE_ID (documents: $(
        jq -r --arg key "$INSTANCE_ID_ANNOTATION" '[.items[] | "\(.metadata.name) [\(.metadata.annotations[$key] // "no instance-id")]"]
          | join(", ")' "$BATS_TEST_TMPDIR/vex-documents.json"))"
    elif [ -z "$uuid" ]; then
      diagnosis="no Dependency-Track project '$IMAGE' version '$TAG'"
    else
      name="$(jq -r '.metadata.name' <<<"$document")"
      version="$(jq -c '.spec.version' <<<"$document")"
      jq '.spec' <<<"$document" >"$BATS_TEST_TMPDIR/runtime-openvex.json"
      runtime_statements "$BATS_TEST_TMPDIR/runtime-openvex.json" "$attested" "$statements"
      required="$(required_pairs "$statements")"
      entries="$BATS_TEST_TMPDIR/entries.json"
      dt_bridge_entries "$IMAGE" "$TAG" "$since" "$entries" || return 1
      uploaded="$(jq -c --arg doc "$KUBESCAPE_NAMESPACE/$name" --argjson version "$version" \
        '[.[] | select(.message == "Kubescape VEX uploaded" and .kubescape == $doc and .kubescape_version == $version)]
          | last // empty' "$entries")"

      if [ "$(jq length <<<"$required")" -eq 0 ]; then
        diagnosis="Kubescape document $name (version $version) has $(jq length "$statements") statement(s), $(
          jq '[.[] | select(.status == "not_affected")] | length' "$statements") not_affected, none covering an attested component of $IMAGE@$DIGEST that no other statement contests: the check would be vacuous"
      elif [ -z "$uploaded" ]; then
        diagnosis="dt-bridge logged no 'Kubescape VEX uploaded' for $KUBESCAPE_NAMESPACE/$name version $version on $IMAGE:$TAG since the restart (its messages about $IMAGE:$TAG: $(
          jq -r '[.[] | .message + (if .kubescape then " \(.kubescape) v\(.kubescape_version)" else "" end)
            + (if .error then " (\(.error))" else "" end)] | unique | join("; ")' "$entries"))"
      else
        token="$(jq -r '.token // ""' <<<"$uploaded")"
        [[ "$token" =~ $UUID_RE ]] ||
          fail "the 'Kubescape VEX uploaded' entry of $IMAGE:$TAG carries no Dependency-Track token: $(jq -c 'del(.vex)' <<<"$uploaded")"
        [ "$(jq -r '.digest // ""' <<<"$uploaded")" = "$DIGEST" ] ||
          fail "the 'Kubescape VEX uploaded' entry of $IMAGE:$TAG names digest $(jq -r '.digest // "none"' <<<"$uploaded"), not the running $DIGEST"
        [ "$(jq -r '.project_uuid // ""' <<<"$uploaded")" = "$uuid" ] ||
          fail "the Kubescape VEX of $IMAGE:$TAG was accepted for project $(jq -r '.project_uuid // "none"' <<<"$uploaded"), not '$IMAGE' version '$TAG' ($uuid)"
        jq '.vex' <<<"$uploaded" >"$BATS_TEST_TMPDIR/vex.json"
        jq -e 'type == "object"' "$BATS_TEST_TMPDIR/vex.json" >/dev/null ||
          fail "the 'Kubescape VEX uploaded' entry of $IMAGE:$TAG carries no VEX document"

        dt_components "$uuid" "$BATS_TEST_TMPDIR/dt-components.json" || return 1
        jq "$PURL_JQ"' [.[] | .purl // empty | purl_norm] | unique' "$BATS_TEST_TMPDIR/dt-components.json" \
          >"$BATS_TEST_TMPDIR/dt-purls.json"
        dt_findings "$uuid" "$BATS_TEST_TMPDIR/findings.json" || return 1
        problems="$(runtime_vex_problems "$BATS_TEST_TMPDIR/vex.json" "$statements" "$attested" \
          "$BATS_TEST_TMPDIR/dt-purls.json" "$BATS_TEST_TMPDIR/findings.json")"
        [ -z "$problems" ] ||
          fail "the VEX dt-bridge uploaded for $IMAGE:$TAG is not the conversion of Kubescape document $name version $version: $(head -n 10 <<<"$problems" | paste -sd ';' -)"

        dt_get "/v1/event/token/$token" || return 1
        [ "$HTTP_CODE" = 200 ] || fail "cannot read Dependency-Track token $token (HTTP $HTTP_CODE)"
        status="$(jq -r '.status // "none"' "$HTTP_BODY")"
        [ "$status" != FAILED ] || fail "Dependency-Track failed to process the Kubescape VEX of $IMAGE:$TAG (token $token)"

        # Once Dependency-Track lists findings a runtime not_affected statement covers (same vulnerability by DT
        # id or alias, on a component it covers, uncontested at runtime), each must carry that analysis.
        jq -n "$RUNTIME_JQ"' input as $statements | input as $findings
          | [$statements[] | select(.status != "not_affected")] as $other | [
            $findings[] as $f
            | ([$f.vulnerability.vulnId] + [$f.vulnerability.aliases[]? | .[]? | strings]) as $finding_ids
            | ($f.component.purl // "") as $component
            | select($component != "")
            | select(any($other[]; any(.ids[]; IN($finding_ids[])) and any(.products[]; purl_covers(.; $component)))
                | not)
            | $statements[] | select(.status == "not_affected" and any(.ids[]; IN($finding_ids[]))
                and any(.products[]; purl_covers(.; $component)))
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
          diagnosis="Dependency-Track has not completed the Kubescape VEX of $IMAGE:$TAG (token $token, status $status)"
        elif [ -n "$offenders" ]; then
          diagnosis="$(jq length "$BATS_TEST_TMPDIR/covered.json") finding(s) covered by runtime not_affected statements, not applied as expected: $offenders"
        else
          echo "# Kubescape document $name version $version: $(jq length <<<"$required") required pair(s); VEX token $token COMPLETED with $(jq '.vulnerabilities | length' "$BATS_TEST_TMPDIR/vex.json") vulnerabilities on $(jq '.components | length' "$BATS_TEST_TMPDIR/vex.json") components; $(jq length "$BATS_TEST_TMPDIR/covered.json") DT finding(s) covered" >&3
          return 0
        fi
      fi
    fi
    [ "$SECONDS" -lt "$deadline" ] || fail "${RUNTIME_VEX_TIMEOUT_SECONDS}s after restarting $WORKLOAD_NAMESPACE/$WORKLOAD_DEPLOYMENT: $diagnosis"
    sleep 15
  done
}

@test "dt-bridge reads Kubescape VEX documents with read-only access" {
  kubectl -n "$DT_BRIDGE_NAMESPACE" get serviceaccount dt-bridge >/dev/null 2>&1 ||
    fail "ServiceAccount $DT_BRIDGE_NAMESPACE/dt-bridge not found"
  can() {
    kubectl auth can-i "$@" --as="$DT_BRIDGE_SUBJECT" >/dev/null 2>&1
  }

  missing=()
  for verb in get list; do
    can "$verb" "$VEX_RESOURCE" -n "$KUBESCAPE_NAMESPACE" || missing+=("$verb")
  done
  [ "${#missing[@]}" -eq 0 ] ||
    fail "$DT_BRIDGE_SUBJECT cannot ${missing[*]} $VEX_RESOURCE in namespace $KUBESCAPE_NAMESPACE"

  granted=()
  for verb in create update patch delete deletecollection; do
    can "$verb" "$VEX_RESOURCE" -n "$KUBESCAPE_NAMESPACE" && granted+=("$verb $VEX_RESOURCE in $KUBESCAPE_NAMESPACE")
  done
  can list "$VEX_RESOURCE" --all-namespaces && granted+=("list $VEX_RESOURCE cluster-wide")
  can list "$VEX_RESOURCE" -n "$WORKLOAD_NAMESPACE" && granted+=("list $VEX_RESOURCE in $WORKLOAD_NAMESPACE")
  for resource in secrets configmaps "vulnerabilitymanifests.$KUBESCAPE_GROUP" "sbomsyfts.$KUBESCAPE_GROUP" \
    "applicationprofiles.$KUBESCAPE_GROUP"; do
    can get "$resource" -n "$KUBESCAPE_NAMESPACE" && granted+=("get $resource in $KUBESCAPE_NAMESPACE")
  done
  can list secrets -n "$DT_BRIDGE_NAMESPACE" && granted+=("list secrets in $DT_BRIDGE_NAMESPACE")
  can create pods -n "$DT_BRIDGE_NAMESPACE" && granted+=("create pods in $DT_BRIDGE_NAMESPACE")
  [ "${#granted[@]}" -eq 0 ] || fail "$DT_BRIDGE_SUBJECT is allowed beyond reading Kubescape VEX documents: ${granted[*]}"
}
