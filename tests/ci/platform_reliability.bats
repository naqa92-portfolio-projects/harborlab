#!/usr/bin/env bats
# Platform manifests and bootstrap scripts, checked without a cluster: Argo CD Applications rendered with
# helm, and the functions of scripts/platform-up.sh run against a fake kubectl or in a temporary directory.
# platform-up.sh defines its functions first, then runs them from the line `WORK="$(mktemp -d)"`: the
# tests source everything above that line.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
APPS_CHART=platform/apps
PLATFORM_UP=scripts/platform-up.sh
DEMO_ADMISSION=scripts/demo-admission.sh
DT_BRIDGE_SRC=apps/dt-bridge/src
RUNTIME_DEMO_PROFILE=platform/workloads/runtime-demo/containerprofile.yaml
RESOURCES_FINALIZER=resources-finalizer.argocd.argoproj.io
VICTORIA_LOGS_MIN_LIMIT_MI=512
# Grafana 13 with the VictoriaLogs plugin backend is OOMKilled at 448Mi when Explore opens that datasource.
GRAFANA_MIN_LIMIT_MI=768

fail() {
  echo "$*" >&2
  return 1
}

# Every Application the app-of-apps chart renders, as one JSON array.
rendered_applications() {
  helm template root "$REPO_ROOT/$APPS_CHART" --set revision=main |
    yq -o=json -I=0 'select(.kind == "Application")' | jq -s '.'
}

# Sources the function part of platform-up.sh into the current shell.
source_platform_up_functions() {
  local functions="$BATS_TEST_TMPDIR/platform-up-functions.sh"
  sed '/^WORK="\$(mktemp -d)"$/,$d' "$REPO_ROOT/$PLATFORM_UP" >"$functions"
  [ "$(wc -l <"$functions")" -lt "$(wc -l <"$REPO_ROOT/$PLATFORM_UP")" ] ||
    fail "$PLATFORM_UP has no top-level line WORK=\"\$(mktemp -d)\" separating its functions from its run"
  # shellcheck disable=SC1090
  source "$functions"
}

memory_mi() {
  local value="$1"
  case "$value" in
    *Gi) echo $((${value%Gi} * 1024)) ;;
    *Mi) echo "${value%Mi}" ;;
    *G) echo $((${value%G} * 1000 * 1000 * 1000 / 1048576)) ;;
    *M) echo $((${value%M} * 1000 * 1000 / 1048576)) ;;
    *) echo 0 ;;
  esac
}

@test "every Argo CD Application prunes its resources when deleted" {
  run rendered_applications
  [ "$status" -eq 0 ] || fail "helm template $APPS_CHART failed: $output"
  [ "$(jq 'length' <<<"$output")" -gt 0 ] || fail "$APPS_CHART renders no Application"
  missing="$(jq -r --arg f "$RESOURCES_FINALIZER" '.[]
    | select(any(.metadata.finalizers[]?; . == $f or startswith($f + "/")) | not) | .metadata.name' <<<"$output")"
  [ -z "$missing" ] || fail "Applications without the $RESOURCES_FINALIZER finalizer: $(tr '\n' ' ' <<<"$missing")"
}

@test "task up convergence wait returns on a Synced and Healthy Application Argo CD never operated" {
  fake="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$fake"
  state="$BATS_TEST_TMPDIR/argocd"
  mkdir -p "$state"
  old="$(date -u -d '-10 minutes' +%Y-%m-%dT%H:%M:%SZ)"
  # hello-java: Synced and Healthy for 10 minutes, created on resources already in their desired state,
  # so automated sync never ran an operation and status.operationState is absent.
  jq -n --arg old "$old" '{items: [
      {metadata: {name: "root", namespace: "argocd"},
       status: {sync: {status: "Synced"}, health: {status: "Healthy", lastTransitionTime: $old},
                operationState: {phase: "Succeeded", finishedAt: $old}}},
      {metadata: {name: "hello-java", namespace: "argocd"},
       status: {sync: {status: "Synced"}, health: {status: "Healthy", lastTransitionTime: $old}}}
    ]}' >"$state/applications.json"
  # Fake kubectl: serves the Applications; a sync requested through the Application's operation field
  # (patch or annotate) completes at once, as Argo CD would for an in-sync Application.
  cat >"$fake/kubectl" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$state/calls.log"
case "\$*" in
  *"get app"*) cat "$state/applications.json" ;;
  *patch*application*operation*|*annotate*application*)
    name="\$(tr ' ' '\n' <<<"\$*" | grep -E '^(applications?(\.argoproj\.io)?/)?hello-java\$' | sed 's#.*/##')"
    [ -n "\$name" ] || exit 0
    jq --arg old "$old" '(.items[] | select(.metadata.name == "hello-java") | .status.operationState)
      = {phase: "Succeeded", finishedAt: \$old}' "$state/applications.json" >"$state/next.json"
    mv "$state/next.json" "$state/applications.json" ;;
  *) exit 0 ;;
esac
EOF
  chmod +x "$fake/kubectl"
  cat >"$fake/argocd" <<EOF
#!/usr/bin/env bash
echo "argocd \$*" >>"$state/calls.log"
exit 1
EOF
  chmod +x "$fake/argocd"

  sed '/^WORK="\$(mktemp -d)"$/,$d' "$REPO_ROOT/$PLATFORM_UP" >"$BATS_TEST_TMPDIR/functions.sh"
  run timeout 90 bash -c 'export PATH="$1:$PATH"; source "$2"; WORK="$3"; wait_for_convergence' \
    _ "$fake" "$BATS_TEST_TMPDIR/functions.sh" "$BATS_TEST_TMPDIR"
  [ "$status" -eq 0 ] ||
    fail "wait_for_convergence did not return within 90 s (exit $status) on hello-java Synced and Healthy without operationState:"$'\n'"$(tail -n 5 <<<"$output")"$'\n'"kubectl calls: $(sort -u "$state/calls.log" | tr '\n' ';')"
}

@test "runtime-demo ContainerProfile changes in git reach the cluster" {
  run rendered_applications
  [ "$status" -eq 0 ] || fail "helm template $APPS_CHART failed: $output"
  application="$(jq -c '.[] | select(.metadata.name == "runtime-demo")' <<<"$output")"
  [ -n "$application" ] || fail "$APPS_CHART renders no runtime-demo Application"
  ignored="$(jq -c '[.spec.ignoreDifferences[]? | select(.kind == "ContainerProfile")
    | select(any(.jsonPointers[]?; . == "/spec") or any(.jqPathExpressions[]?; . == ".spec"))]' <<<"$application")"
  [ "$ignored" = "[]" ] && return 0
  # A /spec ignore is acceptable only with a sync trigger: an annotation holding the SHA-256 of the
  # canonical spec (jq -cS), so that a spec change in git changes the live object's metadata.
  spec_hash="$(yq -o=json '.spec' "$REPO_ROOT/$RUNTIME_DEMO_PROFILE" | jq -cS '.' | tr -d '\n' | sha256sum | cut -d' ' -f1)"
  yq -o=json '.metadata.annotations // {}' "$REPO_ROOT/$RUNTIME_DEMO_PROFILE" |
    jq -e --arg h "$spec_hash" 'any(.[]; . == $h or . == "sha256:" + $h)' >/dev/null ||
    fail "Application runtime-demo ignores ContainerProfile /spec ($ignored) and $RUNTIME_DEMO_PROFILE carries no annotation with its spec hash $spec_hash: git changes to the profile never sync"
}

@test "VictoriaLogs server memory limit is at least 512Mi" {
  run rendered_applications
  [ "$status" -eq 0 ] || fail "helm template $APPS_CHART failed: $output"
  limit="$(jq -r '.[] | select(.metadata.name == "victoria-logs")
    | [(.spec.sources // [.spec.source])[] | select(.chart == "victoria-logs-single")][0]
    | .helm.valuesObject.server.resources.limits.memory // ""' <<<"$output")"
  [ -n "$limit" ] || fail "Application victoria-logs sets no server memory limit"
  [ "$(memory_mi "$limit")" -ge "$VICTORIA_LOGS_MIN_LIMIT_MI" ] ||
    fail "VictoriaLogs server memory limit $limit is below ${VICTORIA_LOGS_MIN_LIMIT_MI}Mi"
}

@test "Grafana memory limit is at least 768Mi" {
  run rendered_applications
  [ "$status" -eq 0 ] || fail "helm template $APPS_CHART failed: $output"
  limit="$(jq -r '.[] | select(.metadata.name == "grafana")
    | [(.spec.sources // [.spec.source])[] | select(.chart == "grafana")][0]
    | .helm.valuesObject.resources.limits.memory // ""' <<<"$output")"
  [ -n "$limit" ] || fail "Application grafana sets no memory limit"
  [ "$(memory_mi "$limit")" -ge "$GRAFANA_MIN_LIMIT_MI" ] ||
    fail "Grafana memory limit $limit is below ${GRAFANA_MIN_LIMIT_MI}Mi"
}

@test "local CA is generated with CA basic constraints and certificate signing key usage" {
  source_platform_up_functions
  CA_DIR="$BATS_TEST_TMPDIR/ca"
  ensure_ca 2>/dev/null
  [ -s "$CA_DIR/ca.crt" ] || fail "ensure_ca wrote no $CA_DIR/ca.crt"
  text="$(openssl x509 -in "$CA_DIR/ca.crt" -noout -text)"
  grep -A1 'X509v3 Basic Constraints: critical' <<<"$text" | grep -q 'CA:TRUE' ||
    fail "the local CA has no critical basicConstraints CA:TRUE"
  usage="$(grep -A1 'X509v3 Key Usage: critical' <<<"$text" | tail -n 1 || true)"
  grep -q 'Certificate Sign' <<<"$usage" && grep -q 'CRL Sign' <<<"$usage" ||
    fail "the local CA has no critical keyUsage keyCertSign, cRLSign (got: ${usage:-none})"
}

@test "dt-bridge verifies TLS with strict X.509 checks" {
  relaxed="$(grep -rn --include='*.py' 'VERIFY_X509_STRICT\|relax_x509' "$REPO_ROOT/$DT_BRIDGE_SRC" || true)"
  [ -z "$relaxed" ] || fail "dt-bridge still relaxes X.509 verification: $relaxed"
}

@test "admission demos consume fixtures by an immutable reference and never tolerate a failed replication" {
  script="$REPO_ROOT/$DEMO_ADMISSION"
  moving="$(grep -nE 'artifacts/e2e|:e2e\b' "$script" | grep -vE '^[0-9]+:[[:space:]]*#' || true)"
  [ -z "$moving" ] || fail "$DEMO_ADMISSION looks fixtures up by the moving tag e2e: $moving"
  tolerated="$(grep -nE 'replicate[^|]*\|\|' "$script" | grep -vE '^[0-9]+:[[:space:]]*#' || true)"
  [ -z "$tolerated" ] || fail "$DEMO_ADMISSION carries on after a failed replication: $tolerated"
}
