#!/usr/bin/env bats
# Demo scenarios, live: each `task demo:<scenario>` exits 0 when the platform reacts as docs/DEMO.md documents,
# and an admission scenario run in a namespace without the workload label, where nothing reacts, exits non-zero.

bats_require_minimum_version 1.5.0

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
load ../supply-chain/golden
load dt
load grafana

ADMISSION_SCENARIOS=(unsigned foreign-signer non-golden-base deprecated-base eol-base direct-dockerhub root)
ADMISSION_TIMEOUT_SECONDS=180
RUNTIME_SHELL_TIMEOUT_SECONDS=120
VEX_TIMEOUT_SECONDS=900
# VictoriaLogs ingestion delay allowed after the task has returned; the alert itself must predate the return.
ALERT_INGEST_SECONDS=60
POLL_SECONDS=5
CONTROL_NAMESPACE=harborlab-demo-control
GOLDEN_IMAGES_CONFIGMAP=golden-images
KYVERNO_NAMESPACE=kyverno
BUILD_IDENTITY='^https://github\.com/naqa92-portfolio-projects/harborlab/\.github/workflows/build-image\.yml@refs/heads/(main|prd-.+)$'
HARBOR_WORKLOAD_RE='^harbor\.127\.0\.0\.1\.nip\.io/(golden|apps)/'
DOCKER_HUB_HOSTS_RE='^(docker\.io|index\.docker\.io|registry-1\.docker\.io)$'
RUNTIME_TARGET_RE='^runtime-shell target: ([a-z0-9-]+)/([a-z0-9.-]+)/([a-z0-9-]+)$'
RUNTIME_ALERT_RE='^runtime-shell alert: (.+)$'
VEX_LINE_RE='^vex accepted: ([a-z0-9._-]+/[a-z0-9._/-]+):([A-Za-z0-9._-]+) token ([0-9a-f-]{36})$'
SHELL_RE='(^|[ (/:"])(sh|bash|dash|ash|busybox)([ )"]|$)'
DENIAL_RE='denied the request|violates PodSecurity|Warning: .*workload-'

setup_file() {
  grafana_setup_file
}

setup() {
  grafana_setup
  dt_setup
  PROBLEMS=()
}

teardown() {
  kubectl delete namespace "$CONTROL_NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

problem() {
  PROBLEMS+=("$*")
}

# Runs `task <args>` from the repository root under a timeout of $1 seconds, stdout and stderr merged into
# `output`; sets `status`, TASK_START and TASK_END (epoch seconds).
run_task() {
  local seconds="$1"
  shift
  TASK_START="$(date +%s)"
  run bash -c "cd '$REPO_ROOT' && timeout $seconds task $* 2>&1"
  TASK_END="$(date +%s)"
}

# API server answer the scenario $1 must show: deny or warn, and the text it contains.
expected_reaction() {
  case "$1" in
    unsigned | foreign-signer)
      EXPECT_ACTION=deny
      EXPECT_TEXT='Policy workload-image-signature failed: image is not signed by the harborlab build-image workflow'
      ;;
    non-golden-base)
      EXPECT_ACTION=deny
      EXPECT_TEXT='Policy workload-golden-base failed: image base is not a golden image of the catalog'
      ;;
    eol-base)
      EXPECT_ACTION=deny
      EXPECT_TEXT='Policy workload-golden-base failed: image base is an end-of-life golden image'
      ;;
    direct-dockerhub)
      EXPECT_ACTION=deny
      EXPECT_TEXT='Policy workload-registry failed: image is not served from an allowed workload registry'
      ;;
    root)
      EXPECT_ACTION=deny
      EXPECT_TEXT='violates PodSecurity "restricted:latest"'
      ;;
    deprecated-base)
      EXPECT_ACTION=warn
      EXPECT_TEXT='image base is a deprecated golden image'
      ;;
  esac
}

# Registry host of the image reference $1 (a reference without host is on docker.io).
image_host() {
  local first="${1%%/*}"
  if [[ "$1" == */* && ( "$first" == *.* || "$first" == *:* || "$first" == localhost ) ]]; then
    echo "$first"
  else
    echo docker.io
  fi
}

# Status of the base recorded in the SLSA provenance of $1 (verified against the build identity) in the live
# ConfigMap kyverno/golden-images: supported, deprecated, eol or absent. Fails when the provenance does not verify.
base_status() {
  local provenance="$BATS_TEST_TMPDIR/provenance.json" hex
  cosign verify-attestation --certificate-oidc-issuer "$OIDC_ISSUER" --certificate-identity-regexp "$BUILD_IDENTITY" \
    --type slsaprovenance1 --registry-cacert "$PLATFORM_CA" "$1" >"$provenance" 2>/dev/null || return 1
  hex="$(attestation_statements "$provenance" | jq -r '[.[].predicate.buildDefinition.resolvedDependencies[]?
      | select((.uri // "") | startswith("oci://")) | .digest.sha256 // empty] | unique
      | if length == 1 then .[0] else "" end')"
  [[ "$hex" =~ ^[0-9a-f]{64}$ ]] || return 1
  kubectl -n "$KYVERNO_NAMESPACE" get configmap "$GOLDEN_IMAGES_CONFIGMAP" -o json |
    jq -r --arg k "sha256.$hex" '.data[$k] // "absent"'
}

# Checks one admission scenario run (bats `output`/`status` of run_task) against the platform's reaction.
check_admission_scenario() {
  local scenario="$1" line namespace pod image host status_of_base
  local target_re="^demo:$scenario target: ([a-z0-9-]+)/([a-z0-9.-]+) image: ([^[:space:]]+)$"
  expected_reaction "$scenario"
  line="$(grep -E "$target_re" <<<"$output" | tail -n 1)"
  if ! [[ "$line" =~ $target_re ]]; then
    problem "demo:$scenario exited $status and printed no 'demo:$scenario target: <namespace>/<pod> image: <reference>' line: $(tail -n 3 <<<"$output" | paste -sd ' ' -)"
    return 0
  fi
  namespace="${BASH_REMATCH[1]}" pod="${BASH_REMATCH[2]}" image="${BASH_REMATCH[3]}"
  [ "$status" -eq 0 ] || problem "demo:$scenario exited $status: $(tail -n 3 <<<"$output" | paste -sd ' ' -)"
  kubectl get namespace -l "$WORKLOAD_LABEL" -o name | grep -qx "namespace/$namespace" ||
    problem "demo:$scenario targets namespace $namespace, which is not labelled $WORKLOAD_LABEL"
  grep -qF -- "$EXPECT_TEXT" <<<"$output" ||
    problem "demo:$scenario output lacks the API server answer '$EXPECT_TEXT'"

  host="$(image_host "$image")"
  if [ "$scenario" = direct-dockerhub ]; then
    [[ "$host" =~ $DOCKER_HUB_HOSTS_RE ]] || problem "demo:$scenario submits $image, not a Docker Hub image"
  else
    [[ "$image" =~ $HARBOR_WORKLOAD_RE ]] ||
      problem "demo:$scenario submits $image, not a Harbor golden/apps image (the registry policy would decide)"
  fi

  if [ "$EXPECT_ACTION" = deny ]; then
    ! kubectl -n "$namespace" get pod "$pod" -o name >/dev/null 2>&1 ||
      problem "demo:$scenario: pod $namespace/$pod exists although the scenario is denied"
  else
    grep -E '^Warning: ' <<<"$output" | grep -F 'workload-golden-base-deprecated' | grep -qF -- "$EXPECT_TEXT" ||
      problem "demo:$scenario output has no 'Warning:' line naming workload-golden-base-deprecated"
    if kubectl -n "$namespace" get pod "$pod" -o json >"$BATS_TEST_TMPDIR/pod.json" 2>/dev/null; then
      jq -e --arg re "$HARBOR_WORKLOAD_RE" \
        'all(.spec.containers[]; (.image | test($re)) and (.image | test("@sha256:[0-9a-f]{64}$")))' \
        "$BATS_TEST_TMPDIR/pod.json" >/dev/null ||
        problem "demo:$scenario: admitted pod $namespace/$pod runs $(jq -c '[.spec.containers[].image]' "$BATS_TEST_TMPDIR/pod.json"), not Harbor digest references"
    else
      problem "demo:$scenario: admitted pod $namespace/$pod does not exist"
    fi
  fi

  case "$scenario" in
    unsigned)
      ! cosign verify --certificate-identity-regexp '.+' --certificate-oidc-issuer-regexp '.+' \
        --registry-cacert "$PLATFORM_CA" "$image" >/dev/null 2>&1 ||
        problem "demo:$scenario submits $image, which carries a verifiable signature"
      ;;
    foreign-signer)
      cosign verify --certificate-identity-regexp '.+' --certificate-oidc-issuer-regexp '.+' \
        --registry-cacert "$PLATFORM_CA" "$image" >/dev/null 2>&1 ||
        problem "demo:$scenario submits $image, which carries no keyless signature at all"
      ! cosign verify --certificate-identity-regexp "$BUILD_IDENTITY" --certificate-oidc-issuer "$OIDC_ISSUER" \
        --registry-cacert "$PLATFORM_CA" "$image" >/dev/null 2>&1 ||
        problem "demo:$scenario submits $image, which is signed by the build-image.yml identity"
      ;;
    non-golden-base | eol-base | deprecated-base)
      if status_of_base="$(base_status "$image")"; then
        case "$scenario:$status_of_base" in
          non-golden-base:absent | eol-base:eol | deprecated-base:deprecated) ;;
          *) problem "demo:$scenario submits $image, whose provenance base is '$status_of_base' in $KYVERNO_NAMESPACE/$GOLDEN_IMAGES_CONFIGMAP" ;;
        esac
      else
        problem "demo:$scenario submits $image, whose SLSA provenance does not verify against the build identity with exactly one oci:// base"
      fi
      ;;
  esac
}

# Kubescape alert rows about container $3 of pod $1/$2 in the /api/ds/query response in HTTP_BODY, time within
# [$4, $5] (epoch ms), as a JSON array of {time, text}.
alert_rows() {
  jq -c --arg ns "$1" --arg pod "$2" --arg container "$3" --argjson since "$4" --argjson until "$5" "$GRAFANA_JQ"'
    [rows[] | {time: ([.[] | select(.type == "time") | .value] | first // 0),
        text: ([.[] | .value, (.labels | tostring)] | map(tostring) | join(" "))}
      | select(.time >= $since and .time <= $until)
      | select(.text | contains($pod) and contains($ns) and contains($container))]' "$HTTP_BODY"
}

check_runtime_shell() {
  local target namespace pod container image deadline alerts shell_alerts
  if [ "$status" -ne 0 ]; then
    problem "demo:runtime-shell exited $status within ${RUNTIME_SHELL_TIMEOUT_SECONDS}s (124: timed out; no retry): $(tail -n 3 <<<"$output" | paste -sd ' ' -)"
    return 0
  fi
  target="$(grep -E "$RUNTIME_TARGET_RE" <<<"$output" | tail -n 1)"
  if ! [[ "$target" =~ $RUNTIME_TARGET_RE ]]; then
    problem "demo:runtime-shell printed no 'runtime-shell target: <namespace>/<pod>/<container>' line"
    return 0
  fi
  namespace="${BASH_REMATCH[1]}" pod="${BASH_REMATCH[2]}" container="${BASH_REMATCH[3]}"
  grep -qE "$RUNTIME_ALERT_RE" <<<"$output" ||
    problem "demo:runtime-shell exited 0 without printing the alert it observed ('runtime-shell alert: <text>')"
  kubectl get namespace -l "$WORKLOAD_LABEL" -o name | grep -qx "namespace/$namespace" ||
    problem "demo:runtime-shell target namespace $namespace is not labelled $WORKLOAD_LABEL"
  image="$(kubectl -n "$namespace" get pod "$pod" -o json |
    jq -r --arg c "$container" '.spec.containers[] | select(.name == $c) | .image')"
  [[ "$image" =~ $HARBOR_WORKLOAD_RE && "$image" == *@sha256:* ]] ||
    problem "demo:runtime-shell target $namespace/$pod/$container runs '$image', not a Harbor golden/apps digest"

  jq -n --arg ns "$namespace" --arg pod "$pod" --arg c "$container" '{
      expr: "RuleID:* AND RuntimeK8sDetails.namespace:=\($ns | @json) AND RuntimeK8sDetails.podName:=\($pod | @json) AND RuntimeK8sDetails.containerName:=\($c | @json)",
      queryType: "instant", maxLines: 100}' >"$BATS_TEST_TMPDIR/alert-query.json"
  deadline=$((TASK_END + ALERT_INGEST_SECONDS))
  while :; do
    grafana_ds_query "$VL_DATASOURCE_UID" "$BATS_TEST_TMPDIR/alert-query.json" "$((TASK_START * 1000 - 60000))" \
      "$(($(date +%s) * 1000))" || return 1
    alerts="$(alert_rows "$namespace" "$pod" "$container" "$((TASK_START * 1000))" "$(((TASK_END + LOG_MARGIN_SECONDS) * 1000))")"
    shell_alerts="$(jq -c --arg re "$SHELL_RE" '[.[] | select(.text | test($re))]' <<<"$alerts")"
    [ "$(jq length <<<"$shell_alerts")" -eq 0 ] || return 0
    if [ "$(date +%s)" -ge "$deadline" ]; then
      problem "demo:runtime-shell exited 0 but no Kubescape alert naming a shell in $namespace/$pod/$container was raised between the task's start and its exit ($(jq length <<<"$alerts") alert row(s) in that window)"
      return 0
    fi
    sleep "$POLL_SECONDS"
  done
}

check_vex() {
  local line image tag token uuid entries uploaded catalog_names
  if [ "$status" -ne 0 ]; then
    problem "demo:vex exited $status: $(tail -n 3 <<<"$output" | paste -sd ' ' -)"
    return 0
  fi
  line="$(grep -E "$VEX_LINE_RE" <<<"$output" | tail -n 1)"
  if ! [[ "$line" =~ $VEX_LINE_RE ]]; then
    problem "demo:vex printed no 'vex accepted: <harbor project>/<repository>:<tag> token <token>' line"
    return 0
  fi
  image="${BASH_REMATCH[1]}" tag="${BASH_REMATCH[2]}" token="${BASH_REMATCH[3]}"
  ! grep -q 'NOT_AFFECTED' <<<"$output" ||
    problem "demo:vex claims a NOT_AFFECTED analysis, unobservable while DependencyTrack/dependency-track#6132 is open"
  catalog_names="$(yq -r '.images[].name' "$REPO_ROOT/images/catalog.yaml")"
  [[ "$image" == golden/* ]] && grep -qx "${image#golden/}" <<<"$catalog_names" ||
    problem "demo:vex reports $image, not a catalog golden image (DHI-based)"

  uuid="$(dt_project_uuid "$image" "$tag")" || return 1
  if [ -z "$uuid" ]; then
    problem "demo:vex reports $image:$tag, which is no Dependency-Track project version"
    return 0
  fi
  entries="$BATS_TEST_TMPDIR/entries.json"
  dt_bridge_entries "$image" "$tag" "$(date -u -d "@$((TASK_START - LOG_MARGIN_SECONDS))" +%Y-%m-%dT%H:%M:%SZ)" \
    "$entries" || return 1
  uploaded="$(jq -c --arg t "$token" '[.[] | select(.message == "DHI VEX uploaded" and .token == $t)] | last // empty' "$entries")"
  if [ -z "$uploaded" ]; then
    problem "dt-bridge logged no 'DHI VEX uploaded' entry with token $token for $image:$tag during demo:vex"
  else
    [ "$(jq -r '.project_uuid // ""' <<<"$uploaded")" = "$uuid" ] ||
      problem "demo:vex token $token was accepted for project $(jq -r '.project_uuid // "none"' <<<"$uploaded"), not '$image' version '$tag' ($uuid)"
  fi
  dt_get "/v1/event/token/$token" || return 1
  [ "$HTTP_CODE" = 200 ] && [ "$(jq -r '.status // "none"' "$HTTP_BODY")" = COMPLETED ] ||
    problem "demo:vex exited 0 before Dependency-Track completed the VEX (token $token: HTTP $HTTP_CODE, status $(jq -r '.status // "none"' "$HTTP_BODY" 2>/dev/null))"
}

@test "each demo scenario exits 0 when the platform reacts" {
  for scenario in "${ADMISSION_SCENARIOS[@]}"; do
    run_task "$ADMISSION_TIMEOUT_SECONDS" "demo:$scenario"
    check_admission_scenario "$scenario"
  done

  # No retry: a shell run before node-agent has loaded a just-completed profile raises no alert and must fail.
  run_task "$RUNTIME_SHELL_TIMEOUT_SECONDS" demo:runtime-shell
  check_runtime_shell || return 1

  run_task "$VEX_TIMEOUT_SECONDS" demo:vex
  check_vex || return 1

  [ "${#PROBLEMS[@]}" -eq 0 ] || fail "$(printf '%s\n' "${PROBLEMS[@]}")"
}

@test "demo scenario exits non-zero when the platform does not react" {
  kubectl delete namespace "$CONTROL_NAMESPACE" --ignore-not-found --wait=true >/dev/null
  kubectl create namespace "$CONTROL_NAMESPACE" >/dev/null
  labels="$(kubectl get namespace "$CONTROL_NAMESPACE" -o json | jq -cS '.metadata.labels // {}')"

  for scenario in "${ADMISSION_SCENARIOS[@]}"; do
    run_task "$ADMISSION_TIMEOUT_SECONDS" "demo:$scenario" "NAMESPACE=$CONTROL_NAMESPACE"
    target_re="^demo:$scenario target: $CONTROL_NAMESPACE/[a-z0-9.-]+ image: [^[:space:]]+$"
    if ! grep -qE "$target_re" <<<"$output"; then
      problem "demo:$scenario NAMESPACE=$CONTROL_NAMESPACE exited $status without reaching its admission step in $CONTROL_NAMESPACE: $(tail -n 3 <<<"$output" | paste -sd ' ' -)"
      continue
    fi
    ! grep -qE "$DENIAL_RE" <<<"$output" ||
      problem "demo:$scenario NAMESPACE=$CONTROL_NAMESPACE drew a reaction in a namespace without $WORKLOAD_LABEL: $(grep -E "$DENIAL_RE" <<<"$output" | head -n 1)"
    [ "$status" -ne 0 ] ||
      problem "demo:$scenario NAMESPACE=$CONTROL_NAMESPACE exited 0 although the platform did not react"
  done

  [ "$(kubectl get namespace "$CONTROL_NAMESPACE" -o json | jq -cS '.metadata.labels // {}')" = "$labels" ] ||
    problem "the demo tasks changed the labels of namespace $CONTROL_NAMESPACE"

  [ "${#PROBLEMS[@]}" -eq 0 ] || fail "$(printf '%s\n' "${PROBLEMS[@]}")"
}
