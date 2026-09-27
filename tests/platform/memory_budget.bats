#!/usr/bin/env bats
# Memory budget, live: with every Argo CD Application (observability included) Synced and Healthy, the memory
# `kubectl top nodes` reports for the kind node stays at or below 10 GiB over several metrics-server samples.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
KIND_NODE=harborlab-control-plane
METRICS_APISERVICE=v1beta1.metrics.k8s.io
BUDGET_MI=10240
SAMPLES=4
SAMPLE_INTERVAL_SECONDS=20
# Every component of the platform, observability included; any other Application must converge too.
REQUIRED_APPLICATIONS=(root cert-manager openbao external-secrets cloudnative-pg trust-manager platform-config
  kyverno kyverno-policies harbor dependency-track kubescape dt-bridge hello-java
  metrics-server victoria-metrics victoria-logs grafana policy-reporter)

fail() {
  echo "$*" >&2
  return 1
}

setup() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
}

# kubectl top quantity $1 (Ki, Mi, Gi or bytes) in MiB, rounded up, on stdout.
to_mi() {
  local q="$1"
  case "$q" in
    *Ki) echo $(((${q%Ki} + 1023) / 1024)) ;;
    *Mi) echo "${q%Mi}" ;;
    *Gi) echo $((${q%Gi} * 1024)) ;;
    *[0-9]) echo $(((q + 1048575) / 1048576)) ;;
    *) return 1 ;;
  esac
}

@test "cluster memory stays within 10 GiB" {
  apps="$(kubectl -n argocd get applications.argoproj.io -o json)"
  for app in "${REQUIRED_APPLICATIONS[@]}"; do
    jq -e --arg a "$app" 'any(.items[]; .metadata.name == $a)' <<<"$apps" >/dev/null ||
      fail "Argo CD Application $app does not exist: not every component is running"
  done
  unstable="$(jq -r '[.items[] | select(.status.sync.status != "Synced" or .status.health.status != "Healthy")
    | "\(.metadata.name)=\(.status.sync.status // "?")/\(.status.health.status // "?")"] | join(" ")' <<<"$apps")"
  [ -z "$unstable" ] || fail "Applications not Synced and Healthy: $unstable"

  available="$(kubectl get apiservice "$METRICS_APISERVICE" \
    -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' 2>&1)" ||
    fail "APIService $METRICS_APISERVICE (metrics-server) not found: $available"
  [ "$available" = True ] || fail "APIService $METRICS_APISERVICE is not Available ($available)"

  for sample in $(seq 1 "$SAMPLES"); do
    run kubectl top nodes --no-headers
    [ "$status" -eq 0 ] || fail "kubectl top nodes failed: $output"
    [ "$(wc -l <<<"$output")" -eq 1 ] && [ "$(awk '{print $1}' <<<"$output")" = "$KIND_NODE" ] ||
      fail "kubectl top nodes does not report exactly the node $KIND_NODE: $output"
    memory="$(awk '{print $4}' <<<"$output")"
    used_mi="$(to_mi "$memory")" || fail "cannot read the memory column of kubectl top nodes: $output"
    docker_usage="$(docker stats --no-stream --format '{{.MemUsage}}' "$KIND_NODE" 2>/dev/null || echo unavailable)"
    echo "# sample $sample: kubectl top nodes $memory ($used_mi Mi), docker stats $docker_usage" >&3
    [ "$used_mi" -le "$BUDGET_MI" ] ||
      fail "kubectl top nodes reports $used_mi Mi on $KIND_NODE, above the ${BUDGET_MI} Mi budget (sample $sample; docker stats: $docker_usage)"
    [ "$sample" -eq "$SAMPLES" ] || sleep "$SAMPLE_INTERVAL_SECONDS"
  done
}
