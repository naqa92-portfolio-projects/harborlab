#!/usr/bin/env bats
# Image posture in Grafana and Policy Reporter, live: the `image-posture` dashboard shows, per golden image (a catalog
# name, whatever its versions), CVE counts before/after VEX of every catalog entry, the signed/attested share of
# running images, admission violations and runtime alerts, each backed by the real sources (Harbor Trivy reports,
# Dependency-Track, cosign, Kyverno, Kubescape); the Policy Reporter UI lists the Kyverno PolicyReports of the cluster.
# DHI_USERNAME and DHI_TOKEN come from the environment; the token only goes through stdin.

bats_require_minimum_version 1.5.0

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
load ../supply-chain/golden
load dt
load grafana

CATALOG=images/catalog.yaml
DASHBOARD_UID=image-posture
GOLDEN_VARIABLE=golden
# Panels, matched on their title (case-insensitive).
CVE_PANEL='cve'
SIGNED_PANEL='signed'
ADMISSION_PANEL='admission'
RUNTIME_PANEL='runtime'
VULN_METRIC=harborlab_image_vulnerabilities
RUNNING_METRIC=harborlab_running_containers
SEVERITIES=(critical high medium low unknown)
HARBOR_REPORT_TYPE='application/vnd.security.vulnerability.report; version=1.1'
GOLDEN_IDENTITY='^https://github\.com/naqa92-portfolio-projects/harborlab/\.github/workflows/(golden|build-image)\.yml@refs/heads/(main|prd-.+)$'
BUILD_IDENTITY='^https://github\.com/naqa92-portfolio-projects/harborlab/\.github/workflows/build-image\.yml@refs/heads/(main|prd-.+)$'
GOLDEN_LABEL=io.harborlab.golden.name
OPENVEX_PREDICATE_TYPE=https://openvex.dev/ns/v0.2.0
INTOTO_ARTIFACT_TYPE=application/vnd.in-toto+json
DENIED_NAMESPACE=dt-bridge
DENIED_DEPLOYMENT=dt-bridge
DENIED_POD=observability-denied-probe
DENYING_POLICY=workload-registry
POLICY_REPORTER_HOST=policy-reporter.127.0.0.1.nip.io
# A source no PolicyReport of the cluster uses (filter control).
ABSENT_SOURCE=harborlab-absent-source
DASHBOARD_RANGE_MS=3600000
METRIC_TIMEOUT_SECONDS=300
EVENT_TIMEOUT_SECONDS=180
DEMO_TIMEOUT_SECONDS=300
POLL_SECONDS=10

setup_file() {
  dt_setup_file
}

setup() {
  dt_setup
  grafana_setup
}

teardown() {
  kubectl -n "$DENIED_NAMESPACE" delete pod "$DENIED_POD" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

now_ms() {
  echo "$(($(date +%s) * 1000))"
}

# Writes to file $2 the targets of the dashboard panel whose title matches $1 (case-insensitive), each with its
# datasource uid resolved from the target or the panel, from the dashboard JSON in DASHBOARD_JSON.
panel_targets() {
  jq --arg re "$1" '[.dashboard.panels[]? | ., (.panels[]?) | select((.title // "") | test($re; "i"))] as $p
    | if ($p | length) != 1 then error("\($p | length) panel(s) titled like \($re)") else $p[0] end
    | . as $panel | [.targets[]? | . + {uid: (.datasource.uid // $panel.datasource.uid // "")}]' \
    "$DASHBOARD_JSON" >"$2"
}

# Writes to file $2 the target in stdin with the golden variable set to $1 and Grafana's range built-ins set
# to the queried hour; refId, datasource and uid are removed (grafana_ds_query adds them).
instantiate_target() {
  jq --arg g "$1" 'del(.refId, .datasource, .uid, .hide) | walk(if type == "string" then
      gsub("\\$\\{golden(:[a-z]+)?\\}|\\$golden\\b"; $g)
      | gsub("\\$\\{?__range_ms\\}?"; "3600000") | gsub("\\$\\{?__range_s\\}?"; "3600")
      | gsub("\\$\\{?__range\\}?"; "1h") | gsub("\\$\\{?__rate_interval\\}?"; "2m")
      | gsub("\\$\\{?__interval_ms\\}?"; "60000") | gsub("\\$\\{?__interval\\}?"; "1m")
    else . end)' >"$2"
}

# Runs every target of the panel titled like $1 with the golden variable set to $2 over the last hour and
# prints the sum of their magnitudes (see GRAFANA_JQ).
panel_magnitude() {
  local pattern="$1" golden="$2" targets="$BATS_TEST_TMPDIR/panel-targets.json" target="$BATS_TEST_TMPDIR/target.json"
  local total=0 count i uid m to
  panel_targets "$pattern" "$targets" || return 1
  count="$(jq length "$targets")"
  to="$(now_ms)"
  for ((i = 0; i < count; i++)); do
    uid="$(jq -r ".[$i].uid" "$targets")"
    jq ".[$i]" "$targets" | instantiate_target "$golden" "$target"
    grafana_ds_query "$uid" "$target" "$((to - DASHBOARD_RANGE_MS))" "$to" >&2 || return 1
    m="$(grafana_magnitude)"
    total="$(jq -n --argjson a "$total" --argjson b "$m" '$a + $b')"
  done
  echo "$total"
}

# Fails unless the VictoriaMetrics targets of the panel titled like $1, with the golden variable set to $2, return at
# least one number over the last hour.
panel_has_data() {
  local pattern="$1" golden="$2" targets="$BATS_TEST_TMPDIR/data-targets.json" target="$BATS_TEST_TMPDIR/data-target.json"
  local numbers=0 count i to
  panel_targets "$pattern" "$targets" || return 1
  count="$(jq length "$targets")"
  for ((i = 0; i < count; i++)); do
    jq ".[$i]" "$targets" | instantiate_target "$golden" "$target"
    to="$(now_ms)"
    grafana_ds_query "$VM_DATASOURCE_UID" "$target" "$((to - DASHBOARD_RANGE_MS))" "$to" || return 1
    numbers=$((numbers + $(jq "$GRAFANA_JQ"' numbers | length' "$HTTP_BODY")))
  done
  [ "$numbers" -gt 0 ] || fail "panel '$pattern' returns no data for golden image $golden"
}

# Series of the PromQL/MetricsQL instant query $1 through the VictoriaMetrics datasource, as a JSON array of
# {labels, value} on stdout.
vm_series() {
  local query="$BATS_TEST_TMPDIR/vm-query.json" to
  jq -n --arg e "$1" '{expr: $e, instant: true, range: false}' >"$query"
  to="$(now_ms)"
  grafana_ds_query "$VM_DATASOURCE_UID" "$query" "$((to - 300000))" "$to" >&2 || return 1
  jq -c "$GRAFANA_JQ"' [rows[][] | select(.type == "number" and (.value | type) == "number") | {labels, value}]' \
    "$HTTP_BODY"
}

# The io.harborlab.golden.name label of the image config of Harbor artifact $1 (`<project>/<repository>@<digest>`).
harbor_golden_label() {
  local ref="$1" path="${1%%@*}"
  harbor_admin GET "/projects/${path%%/*}/repositories/${path#*/}/artifacts/${ref##*@}" || return 1
  [ "$HTTP_CODE" = 200 ] || {
    fail "cannot read Harbor artifact $ref (HTTP $HTTP_CODE)"
    return 1
  }
  jq -r --arg l "$GOLDEN_LABEL" '.extra_attrs.config.Labels[$l] // ""' "$HTTP_BODY"
}

# Severity counts {critical, high, medium, low, unknown} of the JSON array in file $1 whose entries' severity is
# read by the jq path $2.
severity_counts() {
  jq -c "[.[] | ($2 // \"\") | ascii_downcase | if IN(\"critical\", \"high\", \"medium\", \"low\") then . else \"unknown\" end]
    | reduce .[] as \$s ({critical: 0, high: 0, medium: 0, low: 0, unknown: 0}; .[\$s] += 1)" "$1"
}

# Writes to file $2 the most recent DHI OpenVEX document of the base of golden image $1 (a GHCR digest reference),
# the base being the single dhi.io dependency of its verified SLSA provenance.
golden_dhi_openvex() {
  local ref="$1" out="$2" provenance="$BATS_TEST_TMPDIR/provenance.json" bases base_uri base_hex repo digest
  local platform manifest platform_digest referrers statement best="" layer
  cosign verify-attestation --certificate-oidc-issuer "$OIDC_ISSUER" --certificate-identity-regexp "$GOLDEN_IDENTITY" \
    --type slsaprovenance1 "$ref" >"$provenance" 2>/dev/null || fail "SLSA provenance of $ref not verified against $GOLDEN_IDENTITY"
  mapfile -t bases < <(attestation_statements "$provenance" | jq -r '[.[].predicate.buildDefinition.resolvedDependencies[]?
      | select((.uri // "") | startswith("oci://dhi.io/")) | "\(.uri)|\(.digest.sha256 // "")"] | unique[]')
  [ "${#bases[@]}" -eq 1 ] || fail "SLSA provenance of $ref records ${#bases[@]} dhi.io base(s), expected one"
  IFS='|' read -r base_uri base_hex <<<"${bases[0]}"
  repo="${base_uri#oci://}"
  repo="${repo%%@*}"
  [[ "${repo##*/}" != *:* ]] || repo="${repo%:*}"
  digest="sha256:$base_hex"

  platform="$(crane config "$ref" | jq -r '"\(.os)/\(.architecture)"')"
  manifest="$BATS_TEST_TMPDIR/dhi-manifest.json"
  crane manifest "$repo@$digest" >"$manifest" 2>/dev/null || fail "cannot read $repo@$digest with the DHI credentials"
  platform_digest="$(jq -r --arg p "$platform" --arg d "$digest" \
    'if .manifests then ([.manifests[] | select("\(.platform.os)/\(.platform.architecture)" == $p) | .digest][0] // "")
     else $d end' "$manifest")"
  [ -n "$platform_digest" ] || fail "$repo@$digest has no $platform manifest"
  referrers="$BATS_TEST_TMPDIR/dhi-referrers.json"
  crane auth token -H "$repo" 2>/dev/null |
    curl -sSf -H @- -H 'Accept: application/vnd.oci.image.index.v1+json' -o "$referrers" \
      "https://${repo%%/*}/v2/${repo#*/}/referrers/$platform_digest?artifactType=$(jq -rn --arg t "$INTOTO_ARTIFACT_TYPE" '$t | @uri')" ||
    fail "cannot list the referrers of $repo@$platform_digest"
  for digest in $(jq -r --arg t "$OPENVEX_PREDICATE_TYPE" \
    '.manifests[]? | select(.annotations["in-toto.io/predicate-type"] == $t) | .digest' "$referrers"); do
    layer="$(crane manifest "$repo@$digest" | jq -r '.layers[0].digest')"
    statement="$BATS_TEST_TMPDIR/openvex-${digest#sha256:}.json"
    crane blob "$repo@$layer" >"$statement" || fail "cannot fetch the OpenVEX attestation $repo@$digest"
    if [ -z "$best" ] || jq -e -n --slurpfile a "$statement" --slurpfile b "$best" \
      '($a[0].predicate | .last_updated // .timestamp) > ($b[0].predicate | .last_updated // .timestamp)' >/dev/null; then
      best="$statement"
    fi
  done
  [ -n "$best" ] || fail "no OpenVEX attestation among the referrers of $repo@$platform_digest"
  jq '.predicate' "$best" >"$out"
}

# Problems of the CVE series (JSON array in file $1) of golden image $2 against the Harbor Trivy report entries
# (file $3), the DT findings (file $4) and the DHI OpenVEX (file $5), one per line; nothing when they agree.
cve_problems() {
  local harbor dt_before dt_after lower
  harbor="$(severity_counts "$3" '.severity')"
  dt_before="$(severity_counts "$4" '.vulnerability.severity')"
  dt_after="$(jq '[.[] | select((.analysis.state // "") | IN("NOT_AFFECTED", "FALSE_POSITIVE") | not)
    | select(.analysis.isSuppressed != true)]' "$4" >"$BATS_TEST_TMPDIR/dt-open.json" &&
    severity_counts "$BATS_TEST_TMPDIR/dt-open.json" '.vulnerability.severity')"
  # Harbor entries no DHI not_affected statement names: DHI's VEX cannot remove them.
  jq -n "$PURL_JQ"' input as $entries | input as $vex
    | [$vex.statements[] | select(.status == "not_affected") | .vulnerability | [.name] + (.aliases // []) | .[]] as $na
    | [$entries[] | select((.id | IN($na[])) | not)]' "$3" "$5" >"$BATS_TEST_TMPDIR/uncovered.json"
  lower="$(severity_counts "$BATS_TEST_TMPDIR/uncovered.json" '.severity')"
  jq -r -n --arg golden "$2" --argjson harbor "$harbor" --argjson dt_before "$dt_before" --argjson dt_after "$dt_after" \
    --argjson lower "$lower" "$PURL_JQ"' input as $series | input as $entries | input as $vex
    | ($series | map({key: "\(.labels.source)/\(.labels.vex)/\(.labels.severity)", value: .value}) | from_entries) as $v
    | [$vex.statements[] | select(.status != "not_affected") | .vulnerability.name] as $contested
    | [$vex.statements[] | select(.status == "not_affected") | select((.vulnerability.name | IN($contested[])) | not)
        | {ids: ([.vulnerability.name] + (.vulnerability.aliases // [])),
           versions: [.products[]? | (.subcomponents // [.])[] | .["@id"] // empty | purl_parts.version]}] as $uncontested
    | any($entries[]; . as $e | any($uncontested[]; . as $s | ($e.id | IN($s.ids[])) and ($e.version | IN($s.versions[]))))
      as $covered
    | ["critical", "high", "medium", "low", "unknown"] as $sev
    | [
        ($series[] | select(.labels.golden != $golden) | "series \(.labels | tojson) has golden \(.labels.golden | tojson)"),
        (["harbor-trivy", "dependency-track"][] as $src | ["before", "after"][] as $vx | $sev[] as $s
          | select($v["\($src)/\($vx)/\($s)"] == null) | "no series source=\($src) vex=\($vx) severity=\($s)"),
        ($sev[] as $s | select($v["harbor-trivy/before/\($s)"] != null and $v["harbor-trivy/before/\($s)"] != $harbor[$s])
          | "harbor-trivy before \($s) is \($v["harbor-trivy/before/\($s)"]), the Harbor Trivy report holds \($harbor[$s])"),
        ($sev[] as $s | select($v["dependency-track/before/\($s)"] != null and $v["dependency-track/before/\($s)"] != $dt_before[$s])
          | "dependency-track before \($s) is \($v["dependency-track/before/\($s)"]), Dependency-Track lists \($dt_before[$s]) finding(s)"),
        ($sev[] as $s | select($v["dependency-track/after/\($s)"] != null and $v["dependency-track/after/\($s)"] != $dt_after[$s])
          | "dependency-track after \($s) is \($v["dependency-track/after/\($s)"]), Dependency-Track lists \($dt_after[$s]) open finding(s)"),
        ($sev[] as $s | ($v["harbor-trivy/after/\($s)"] // null) as $a | select($a != null)
          | if $a > $harbor[$s] then "harbor-trivy after \($s) is \($a), above its \($harbor[$s]) before VEX"
            elif $a < $lower[$s] then "harbor-trivy after \($s) is \($a), below the \($lower[$s]) report entries no DHI not_affected statement names"
            else empty end),
        (if $covered and ([$sev[] as $s | $v["harbor-trivy/after/\($s)"] // 0] | add) >= ([$sev[] | $harbor[.]] | add)
          then "harbor-trivy after VEX is not below before VEX although DHI states not_affected for report entries (same CVE and version)"
          else empty end)
      ] | .[]' "$1" "$3" "$5"
}

# Sets EXPECTED to the expected running-container series, a sorted JSON array of {golden, namespace, pod, container,
# digest, signed, attested}: every running container of a Harbor golden/apps digest image, verified with cosign
# (results cached in the associative array VERIFIED by digest reference). Also writes RUNNING_BASES, a JSON array of
# {golden, digest, base} per labelled running image: base is the image's own digest for a golden image, the single
# oci:// base of its verified SLSA provenance for an app image ("" when it does not verify or names several).
expected_running() {
  local pods="$BATS_TEST_TMPDIR/pods.json" ref project identity signed attested golden type base provenance_ok rows=()
  local provenance="$BATS_TEST_TMPDIR/running-provenance.json"
  kubectl get pods -A -o json >"$pods"
  mapfile -t rows < <(jq -r --arg h "$HARBOR_HOST/" '.items[] | .metadata as $m | select($m.deletionTimestamp == null)
    | (.spec.containers | map({key: .name, value: .image}) | from_entries) as $images
    | .status.containerStatuses[]? | select(.state.running != null)
    | ([$images[.name], (.imageID | sub("^docker-pullable://"; ""))]
        | map(select(startswith($h) and test("^[^@]+/(golden|apps)/[^@]+@sha256:[0-9a-f]{64}$")))[0] // empty) as $ref
    | "\($m.namespace)|\($m.name)|\(.name)|\($ref | ltrimstr($h))"' "$pods")
  for row in "${rows[@]}"; do
    IFS='|' read -r _ _ _ ref <<<"$row"
    if [ -z "${VERIFIED[$ref]:-}" ]; then
      project="${ref%%/*}"
      identity="$BUILD_IDENTITY"
      [ "$project" != golden ] || identity="$GOLDEN_IDENTITY"
      golden="$(harbor_golden_label "$ref")" || return 1
      signed=false attested=true provenance_ok=true
      cosign verify --certificate-oidc-issuer "$OIDC_ISSUER" --certificate-identity-regexp "$identity" \
        --registry-cacert "$PLATFORM_CA" "$HARBOR_HOST/$ref" >/dev/null 2>&1 && signed=true
      for type in cyclonedx spdxjson slsaprovenance1; do
        cosign verify-attestation --certificate-oidc-issuer "$OIDC_ISSUER" --certificate-identity-regexp "$identity" \
          --registry-cacert "$PLATFORM_CA" --type "$type" "$HARBOR_HOST/$ref" >"$provenance" 2>/dev/null || {
          attested=false
          [ "$type" != slsaprovenance1 ] || provenance_ok=false
        }
      done
      base="${ref##*@}"
      if [ "$project" != golden ]; then
        base=""
        [ "$provenance_ok" != true ] || base="$(attestation_statements "$provenance" |
          jq -r '[.[].predicate.buildDefinition.resolvedDependencies[]? | select((.uri // "") | startswith("oci://"))
            | .digest.sha256 // empty] | unique | if length == 1 then "sha256:" + .[0] else "" end')"
      fi
      VERIFIED[$ref]="$golden|$signed|$attested|$base"
    fi
  done
  for row in "${rows[@]}"; do
    IFS='|' read -r _ _ _ ref <<<"$row"
    IFS='|' read -r golden _ _ base <<<"${VERIFIED[$ref]}"
    jq -n -c --arg g "$golden" --arg d "${ref##*@}" --arg b "$base" '{golden: $g, digest: $d, base: $b}'
  done | jq -s -c 'map(select(.golden != "")) | unique' >"$BATS_TEST_TMPDIR/running-bases.json"
  RUNNING_BASES="$(cat "$BATS_TEST_TMPDIR/running-bases.json")"
  for row in "${rows[@]}"; do
    IFS='|' read -r namespace pod container ref <<<"$row"
    IFS='|' read -r golden signed attested _ <<<"${VERIFIED[$ref]}"
    jq -n -c --arg g "$golden" --arg n "$namespace" --arg p "$pod" --arg c "$container" --arg d "${ref##*@}" \
      --arg s "$signed" --arg a "$attested" \
      '{golden: $g, namespace: $n, pod: $p, container: $c, digest: $d, signed: $s, attested: $a}'
  done | jq -s -c 'map(select(.golden != "")) | sort' >"$BATS_TEST_TMPDIR/expected-running.json"
  EXPECTED="$(cat "$BATS_TEST_TMPDIR/expected-running.json")"
}

@test "image posture dashboard shows every metric per golden image" {
  [ -n "${DHI_USERNAME:-}" ] || fail "DHI_USERNAME is not set in the environment"
  [ -n "${DHI_TOKEN:-}" ] || fail "DHI_TOKEN is not set in the environment"
  # Catalog entries, one per (name, version, digest): a name may list several versions (lifecycle history). A golden
  # image is a catalog name, the value of the image label io.harborlab.golden.name, which carries no version.
  mapfile -t entries < <(yq -r '.images[] | [.name, .version, .digest, .status] | join("|")' "$REPO_ROOT/$CATALOG")
  [ "${#entries[@]}" -gt 0 ] || fail "$CATALOG lists no golden image"
  mapfile -t goldens < <(yq -r '[.images[].name] | unique | .[]' "$REPO_ROOT/$CATALOG")
  # Golden images a running workload must use: those with a supported entry (eol bases are denied at admission).
  mapfile -t supported_goldens < <(yq -r '[.images[] | select(.status == "supported") | .name] | unique | .[]' \
    "$REPO_ROOT/$CATALOG")
  [ "${#supported_goldens[@]}" -gt 0 ] || fail "$CATALOG has no supported entry"

  vm_type="$(grafana_datasource_type "$VM_DATASOURCE_UID")" || return 1
  [[ "$vm_type" == prometheus || "$vm_type" == victoriametrics-metrics-datasource ]] ||
    fail "Grafana datasource $VM_DATASOURCE_UID has type '$vm_type', not a Prometheus-compatible VictoriaMetrics datasource"
  vl_type="$(grafana_datasource_type "$VL_DATASOURCE_UID")" || return 1
  [ "$vl_type" = "$VL_DATASOURCE_TYPE" ] ||
    fail "Grafana datasource $VL_DATASOURCE_UID has type '$vl_type', not $VL_DATASOURCE_TYPE"

  grafana_api GET "/api/dashboards/uid/$DASHBOARD_UID" || return 1
  [ "$HTTP_CODE" = 200 ] || fail "Grafana has no dashboard of uid $DASHBOARD_UID (HTTP $HTTP_CODE)"
  DASHBOARD_JSON="$BATS_TEST_TMPDIR/dashboard.json"
  cp "$HTTP_BODY" "$DASHBOARD_JSON"
  jq -e '.dashboard.title | test("image posture"; "i")' "$DASHBOARD_JSON" >/dev/null ||
    fail "dashboard $DASHBOARD_UID is titled $(jq -c '.dashboard.title' "$DASHBOARD_JSON"), not 'image posture'"

  # The golden variable lists label values of a VictoriaMetrics metric: every catalog image must be among them.
  variable="$(jq -c --arg v "$GOLDEN_VARIABLE" '[.dashboard.templating.list[]? | select(.name == $v)][0] // empty' "$DASHBOARD_JSON")"
  [ -n "$variable" ] || fail "dashboard $DASHBOARD_UID has no '$GOLDEN_VARIABLE' variable"
  [ "$(jq -r '.datasource.uid // ""' <<<"$variable")" = "$VM_DATASOURCE_UID" ] ||
    fail "variable $GOLDEN_VARIABLE does not query the $VM_DATASOURCE_UID datasource: $variable"
  definition="$(jq -r '(.query | if type == "object" then .query else . end) // .definition // ""' <<<"$variable")"
  [[ "$definition" =~ ^label_values\((.+),[[:space:]]*golden\)$ ]] ||
    fail "variable $GOLDEN_VARIABLE is not label_values(<selector>, golden): '$definition'"
  listed="$(vm_series "group by (golden) (${BASH_REMATCH[1]})" | jq -c '[.[].labels.golden] | unique')" || return 1
  for golden in "${goldens[@]}"; do
    jq -e --arg g "$golden" 'index($g) != null' <<<"$listed" >/dev/null ||
      fail "variable $GOLDEN_VARIABLE does not list catalog image $golden (it lists $listed)"
  done

  # Four panels, each querying Grafana's VictoriaMetrics or VictoriaLogs datasource per golden image.
  for pattern in "$CVE_PANEL" "$SIGNED_PANEL" "$ADMISSION_PANEL" "$RUNTIME_PANEL"; do
    panel_targets "$pattern" "$BATS_TEST_TMPDIR/targets.json" 2>"$BATS_TEST_TMPDIR/jq.err" ||
      fail "dashboard $DASHBOARD_UID: $(tail -n 1 "$BATS_TEST_TMPDIR/jq.err")"
    jq -e --arg vm "$VM_DATASOURCE_UID" --arg vl "$VL_DATASOURCE_UID" \
      'length > 0 and all(.[]; .uid == $vm or .uid == $vl)' "$BATS_TEST_TMPDIR/targets.json" >/dev/null ||
      fail "panel '$pattern' has no target or a target outside the $VM_DATASOURCE_UID/$VL_DATASOURCE_UID datasources"
    jq -e 'any(.[]; tostring | test("\\$\\{?golden"))' "$BATS_TEST_TMPDIR/targets.json" >/dev/null ||
      fail "panel '$pattern' does not filter on the $GOLDEN_VARIABLE variable"
  done
  for pattern in "$CVE_PANEL" "$SIGNED_PANEL"; do
    panel_targets "$pattern" "$BATS_TEST_TMPDIR/targets.json"
    jq -e --arg vm "$VM_DATASOURCE_UID" 'all(.[]; .uid == $vm)' "$BATS_TEST_TMPDIR/targets.json" >/dev/null ||
      fail "panel '$pattern' does not query VictoriaMetrics ($VM_DATASOURCE_UID)"
  done

  # Admission violation: the running dt-bridge digest from GHCR in a workload namespace, denied by workload-registry.
  denied_digest="$(kubectl -n "$DENIED_NAMESPACE" get deployment "$DENIED_DEPLOYMENT" -o json |
    jq -r '.spec.template.spec.containers[0].image | capture("@(?<d>sha256:[0-9a-f]{64})$").d // ""')"
  [ -n "$denied_digest" ] || fail "deployment $DENIED_NAMESPACE/$DENIED_DEPLOYMENT does not run a digest reference"
  denied_golden="$(harbor_golden_label "$APPS_PROJECT/$DENIED_DEPLOYMENT@$denied_digest")" || return 1
  [ -n "$denied_golden" ] || fail "$APPS_PROJECT/$DENIED_DEPLOYMENT@$denied_digest has no $GOLDEN_LABEL label"
  declare -A admission_before runtime_before
  for golden in "${goldens[@]}"; do
    admission_before[$golden]="$(panel_magnitude "$ADMISSION_PANEL" "$golden")" || return 1
    runtime_before[$golden]="$(panel_magnitude "$RUNTIME_PANEL" "$golden")" || return 1
  done
  run --separate-stderr kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $DENIED_POD
  namespace: $DENIED_NAMESPACE
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: ghcr.io/$GITHUB_REPO/apps/$DENIED_DEPLOYMENT@$denied_digest
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
EOF
  [ "$status" -ne 0 ] && [[ "$stderr" == *"$DENYING_POLICY"* ]] ||
    fail "the GHCR reference was not denied by $DENYING_POLICY (exit $status): $stderr"

  # Runtime alert: the demo shell in a workload container.
  run --separate-stderr bash -c "cd '$REPO_ROOT' && timeout $DEMO_TIMEOUT_SECONDS task demo:runtime-shell"
  [ "$status" -eq 0 ] || fail "task demo:runtime-shell exited $status: $(tail -n 5 <<<"$stderr")"
  target="$(sed -nE 's#^runtime-shell target: ([a-z0-9-]+)/([a-z0-9.-]+)/([a-z0-9-]+)$#\1 \2 \3#p' <<<"$output" | tail -n 1)"
  [ -n "$target" ] || fail "task demo:runtime-shell printed no 'runtime-shell target: <namespace>/<pod>/<container>' line"
  read -r target_ns target_pod target_container <<<"$target"
  target_ref="$(kubectl -n "$target_ns" get pod "$target_pod" -o json |
    jq -r --arg c "$target_container" '.spec.containers[] | select(.name == $c) | .image')"
  [[ "$target_ref" == "$HARBOR_HOST/"*@sha256:* ]] || fail "runtime-shell target runs '$target_ref', not a Harbor digest"
  target_golden="$(harbor_golden_label "${target_ref#"$HARBOR_HOST/"}")" || return 1
  [ -n "$target_golden" ] || fail "runtime-shell target image $target_ref has no $GOLDEN_LABEL label"

  deadline=$((SECONDS + EVENT_TIMEOUT_SECONDS))
  while :; do
    admission_now="$(panel_magnitude "$ADMISSION_PANEL" "$denied_golden")" || return 1
    runtime_now="$(panel_magnitude "$RUNTIME_PANEL" "$target_golden")" || return 1
    jq -e -n --argjson a "$admission_now" --argjson ab "${admission_before[$denied_golden]}" \
      --argjson r "$runtime_now" --argjson rb "${runtime_before[$target_golden]}" '$a > $ab and $r > $rb' >/dev/null && break
    [ "$SECONDS" -lt "$deadline" ] ||
      fail "within ${EVENT_TIMEOUT_SECONDS}s: admission panel for $denied_golden ${admission_before[$denied_golden]} -> $admission_now (a $DENYING_POLICY denial happened), runtime panel for $target_golden ${runtime_before[$target_golden]} -> $runtime_now (a shell ran in $target_ns/$target_pod/$target_container); both must grow"
    sleep "$POLL_SECONDS"
  done

  # CVE panel data for every golden image; signed/attested panel data for every golden image a workload must run.
  for golden in "${goldens[@]}"; do
    panel_has_data "$CVE_PANEL" "$golden" || return 1
  done
  for golden in "${supported_goldens[@]}"; do
    panel_has_data "$SIGNED_PANEL" "$golden" || return 1
  done

  # CVE series of every catalog entry (each version, whatever its status) agree with Harbor's Trivy report,
  # Dependency-Track and the DHI VEX of its base.
  export DOCKER_CONFIG="$BATS_TEST_TMPDIR/docker"
  (umask 077 && mkdir -p "$DOCKER_CONFIG")
  printf '%s' "$DHI_TOKEN" | crane auth login dhi.io -u "$DHI_USERNAME" --password-stdin >/dev/null 2>&1 ||
    fail "crane auth login dhi.io failed for DHI_USERNAME"
  for entry in "${entries[@]}"; do
    IFS='|' read -r golden version digest entry_status <<<"$entry"
    what="$GOLDEN_PROJECT/$golden@$digest (catalog $golden $version, $entry_status)"
    key="${digest#sha256:}"
    harbor_admin GET "/projects/$GOLDEN_PROJECT/repositories/$golden/artifacts/$digest?with_tag=true"
    [ "$HTTP_CODE" = 200 ] || fail "catalog entry $what is not in Harbor (HTTP $HTTP_CODE)"
    tag="$(jq -r '[.tags[]?.name | select(startswith("sha256-") | not)][0] // ""' "$HTTP_BODY")"
    [ -n "$tag" ] || fail "Harbor holds no image tag for $what"
    harbor_admin GET "/projects/$GOLDEN_PROJECT/repositories/$golden/artifacts/$digest/additions/vulnerabilities"
    [ "$HTTP_CODE" = 200 ] || fail "no Harbor vulnerability report for $what (HTTP $HTTP_CODE)"
    jq --arg t "$HARBOR_REPORT_TYPE" '.[$t].vulnerabilities // []' "$HTTP_BODY" >"$BATS_TEST_TMPDIR/report-$key.json"
    uuid="$(dt_project_uuid "$GOLDEN_PROJECT/$golden" "$tag")" || return 1
    [ -n "$uuid" ] || fail "Dependency-Track has no project $GOLDEN_PROJECT/$golden version $tag ($what)"
    dt_findings "$uuid" "$BATS_TEST_TMPDIR/findings-$key.json" || return 1
    golden_dhi_openvex "$GHCR_GOLDEN/$golden@$digest" "$BATS_TEST_TMPDIR/dhi-$key.json"

    deadline=$((SECONDS + METRIC_TIMEOUT_SECONDS))
    while :; do
      vm_series "$VULN_METRIC{image=\"$GOLDEN_PROJECT/$golden\",digest=\"$digest\"}" >"$BATS_TEST_TMPDIR/series.json" ||
        return 1
      problems="$(cve_problems "$BATS_TEST_TMPDIR/series.json" "$golden" "$BATS_TEST_TMPDIR/report-$key.json" \
        "$BATS_TEST_TMPDIR/findings-$key.json" "$BATS_TEST_TMPDIR/dhi-$key.json")"
      [ -n "$problems" ] || break
      [ "$SECONDS" -lt "$deadline" ] ||
        fail "$VULN_METRIC of $what after ${METRIC_TIMEOUT_SECONDS}s: $(head -n 8 <<<"$problems")"
      sleep "$POLL_SECONDS"
    done
  done

  # Running-container series agree with cosign on every running golden/apps image. Every supported catalog entry
  # runs: a running container is that golden image or an image built on it. A deprecated entry needs no workload
  # (when one runs, e.g. after demo:deprecated-base, it is in the series like any other); an eol one cannot get one.
  declare -A VERIFIED
  deadline=$((SECONDS + METRIC_TIMEOUT_SECONDS))
  while :; do
    expected_running || return 1
    expected="$EXPECTED"
    actual="$(vm_series "$RUNNING_METRIC" | jq -c '[.[] | select(.value == 1) | .labels
      | {golden, namespace, pod, container, digest, signed, attested}] | sort')" || return 1
    [ "$expected" != "$actual" ] || break
    [ "$SECONDS" -lt "$deadline" ] ||
      fail "$RUNNING_METRIC after ${METRIC_TIMEOUT_SECONDS}s differs from the running containers verified with cosign: missing $(jq -c -n --argjson e "$expected" --argjson a "$actual" '$e - $a' | head -c 600), unexpected $(jq -c -n --argjson e "$expected" --argjson a "$actual" '$a - $e' | head -c 600)"
    sleep "$POLL_SECONDS"
  done
  for entry in "${entries[@]}"; do
    IFS='|' read -r golden version digest entry_status <<<"$entry"
    [ "$entry_status" = supported ] || continue
    jq -e --arg g "$golden" --arg d "$digest" 'any(.[]; .golden == $g and (.digest == $d or .base == $d))' \
      <<<"$RUNNING_BASES" >/dev/null ||
      fail "no running container runs supported golden $golden $version ($digest) or an image built on it: its signed/attested share would be vacuous (running: $(head -c 600 <<<"$RUNNING_BASES"))"
  done
}

# Writes to $BATS_TEST_TMPDIR/results.json the Policy Reporter UI results of cluster $1 filtered on namespace $2,
# source $3 and policy $4; prints nothing and fails when the API does not answer 200.
policy_reporter_results() {
  local code
  code="$(curl -sS --cacert "$PLATFORM_CA" -G -o "$BATS_TEST_TMPDIR/results.json" -w '%{http_code}' \
    --data-urlencode "namespaces=$2" --data-urlencode "sources=$3" --data-urlencode "policies=$4" \
    --data-urlencode page=1 --data-urlencode offset=50 \
    "https://$POLICY_REPORTER_HOST/api/$1/namespace-scoped/results")" && [ "$code" = 200 ] ||
    fail "Policy Reporter UI results of $2/$4 with source $3 not readable (HTTP ${code:-none})"
}

@test "Policy Reporter UI lists Kyverno PolicyReports" {
  run curl -sS --cacert "$PLATFORM_CA" -o "$BATS_TEST_TMPDIR/config.json" -w '%{http_code}' \
    "https://$POLICY_REPORTER_HOST/api/config"
  [ "$status" -eq 0 ] && [ "$output" = 200 ] ||
    fail "Policy Reporter UI not reachable at https://$POLICY_REPORTER_HOST/api/config (HTTP $output)"
  cluster="$(jq -r '.default // .clusters[0].slug // ""' "$BATS_TEST_TMPDIR/config.json")"
  [ -n "$cluster" ] || fail "Policy Reporter UI has no cluster: $(head -c 300 "$BATS_TEST_TMPDIR/config.json")"

  mapfile -t expected < <(kubectl get policyreports.wgpolicyk8s.io -A -o json | jq -r '[.items[]
    | .metadata.namespace as $n | .results[]? | select((.source // "") | test("^kyverno"; "i"))
    | "\($n)|\(.source)|\(.policy)"] | unique[]')
  [ "${#expected[@]}" -gt 0 ] || fail "the cluster holds no Kyverno PolicyReport result: the check would be vacuous"

  # The UI's result items carry no source field: the source is proven by the sources= filter, which the UI passes
  # to Policy Reporter core; the control shows that filter excludes the results of another source.
  for entry in "${expected[@]}"; do
    IFS='|' read -r namespace source policy <<<"$entry"
    policy_reporter_results "$cluster" "$namespace" "$source" "$policy"
    jq -e --arg n "$namespace" --arg p "$policy" 'any(.items[]?; .namespace == $n and .policy == $p)' \
      "$BATS_TEST_TMPDIR/results.json" >/dev/null ||
      fail "Policy Reporter UI does not list the $source result of policy $policy in namespace $namespace: $(head -c 300 "$BATS_TEST_TMPDIR/results.json")"
    policy_reporter_results "$cluster" "$namespace" "$ABSENT_SOURCE" "$policy"
    jq -e '(.items // []) | length == 0' "$BATS_TEST_TMPDIR/results.json" >/dev/null ||
      fail "control: Policy Reporter UI lists results of $namespace/$policy for source $ABSENT_SOURCE, so its sources= filter is not applied: $(head -c 300 "$BATS_TEST_TMPDIR/results.json")"
  done
}
