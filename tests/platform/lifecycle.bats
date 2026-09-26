#!/usr/bin/env bats
# Platform lifecycle, live against the kind cluster `harborlab` driven by `task up` / `task down`.
# Tests run in file order: up from a down state, down, then up again.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
CLUSTER=harborlab
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
STABLE_SECONDS=60
# Minimum set of ArgoCD Applications; any other Application must be Synced and Healthy too.
REQUIRED_APPLICATIONS=(root cert-manager openbao external-secrets cloudnative-pg)

fail() {
  echo "$*" >&2
  return 1
}

cluster_exists() {
  kind get clusters 2>/dev/null | grep -qx "$CLUSTER"
}

# Fingerprint of the caller's default kubeconfig, compared without ever printing it.
default_kubeconfig_fingerprint() {
  if [ -f "$HOME/.kube/config" ]; then
    sha256sum "$HOME/.kube/config" | cut -d' ' -f1
  else
    echo absent
  fi
}

# Runs `task <name>` from the repository root; sets TASK_STATUS, TASK_LOG and TASK_EXIT_EPOCH.
run_task() {
  TASK_LOG="$BATS_TEST_TMPDIR/task-$1.log"
  TASK_STATUS=0
  (cd "$REPO_ROOT" && task "$1") >"$TASK_LOG" 2>&1 || TASK_STATUS=$?
  TASK_EXIT_EPOCH="$(date -u +%s)"
  if [ -n "${DHI_TOKEN:-}" ] && grep -qF -f /dev/stdin "$TASK_LOG" <<<"$DHI_TOKEN"; then
    rm -f "$TASK_LOG"
    fail "task $1 printed the DHI token value"
  fi
}

task_log_tail() {
  tail -n 40 "$TASK_LOG"
}

assert_isolated_kubeconfig() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "isolated kubeconfig $PLATFORM_KUBECONFIG missing after task up"
  [ "$(stat -c %a "$PLATFORM_KUBECONFIG")" = 600 ] ||
    fail "isolated kubeconfig $PLATFORM_KUBECONFIG has mode $(stat -c %a "$PLATFORM_KUBECONFIG"), expected 600"
  git -C "$REPO_ROOT" check-ignore -q "$PLATFORM_KUBECONFIG" ||
    fail "isolated kubeconfig $PLATFORM_KUBECONFIG is not git-ignored"
  [ "$(KUBECONFIG="$PLATFORM_KUBECONFIG" kubectl config current-context)" = "kind-$CLUSTER" ] ||
    fail "isolated kubeconfig does not point to kind-$CLUSTER"
}

# Every Application Synced and Healthy, the required ones present; health and the last sync
# operation must have settled at least `min_age` seconds before the reference time.
assert_applications_converged() {
  local reference_epoch="$1" min_age="$2" apps
  apps="$BATS_TEST_TMPDIR/applications.json"
  KUBECONFIG="$PLATFORM_KUBECONFIG" kubectl get applications.argoproj.io -A -o json >"$apps" ||
    fail "cannot list ArgoCD Applications"

  for name in "${REQUIRED_APPLICATIONS[@]}"; do
    jq -e --arg n "$name" 'any(.items[]; .metadata.name == $n)' "$apps" >/dev/null ||
      fail "ArgoCD Application $name does not exist"
  done

  run jq -r '.items[]
    | select(.status.sync.status != "Synced" or .status.health.status != "Healthy")
    | "\(.metadata.namespace)/\(.metadata.name): sync=\(.status.sync.status) health=\(.status.health.status)"' "$apps"
  [ -z "$output" ] || fail "Applications not Synced and Healthy after task exit:"$'\n'"$output"

  run jq -r --argjson ref "$reference_epoch" --argjson age "$min_age" '.items[]
    | . as $a
    | ($a.status.health.lastTransitionTime // "") as $healthy_since
    | ($a.status.operationState.finishedAt // "") as $synced_at
    | select($healthy_since == "" or $synced_at == ""
        or ($ref - ($healthy_since | fromdateiso8601)) < $age
        or ($ref - ($synced_at | fromdateiso8601)) < $age
        or $a.status.operationState.phase != "Succeeded")
    | "\($a.metadata.namespace)/\($a.metadata.name): healthy since \($healthy_since), last sync \($a.status.operationState.phase // "none") at \($synced_at)"' "$apps"
  [ -z "$output" ] ||
    fail "Applications not stable for ${min_age}s before task exit at $(date -u -d "@$reference_epoch" +%FT%TZ):"$'\n'"$output"
}

@test "task up exits 0 with every ArgoCD Application Synced and Healthy for 60s" {
  kind delete cluster --name "$CLUSTER" --kubeconfig "$BATS_TEST_TMPDIR/discarded-kubeconfig" >/dev/null 2>&1 || true
  rm -f "$PLATFORM_KUBECONFIG"
  ! cluster_exists || fail "precondition: kind cluster $CLUSTER still exists"
  default_before="$(default_kubeconfig_fingerprint)"

  run_task up
  [ "$TASK_STATUS" -eq 0 ] || fail "task up exited $TASK_STATUS:"$'\n'"$(task_log_tail)"

  cluster_exists || fail "task up exited 0 but kind cluster $CLUSTER does not exist"
  assert_isolated_kubeconfig
  [ "$(default_kubeconfig_fingerprint)" = "$default_before" ] || fail "task up modified $HOME/.kube/config"
  assert_applications_converged "$TASK_EXIT_EPOCH" "$STABLE_SECONDS"
}

@test "task down removes the cluster and the isolated kubeconfig" {
  cluster_exists || fail "precondition: kind cluster $CLUSTER is not up; task down would prove nothing"
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "precondition: isolated kubeconfig $PLATFORM_KUBECONFIG is missing"
  default_before="$(default_kubeconfig_fingerprint)"

  run_task down
  [ "$TASK_STATUS" -eq 0 ] || fail "task down exited $TASK_STATUS:"$'\n'"$(task_log_tail)"

  ! cluster_exists || fail "kind cluster $CLUSTER still listed after task down"
  [ ! -e "$PLATFORM_KUBECONFIG" ] || fail "isolated kubeconfig $PLATFORM_KUBECONFIG still exists after task down"
  [ "$(default_kubeconfig_fingerprint)" = "$default_before" ] || fail "task down modified $HOME/.kube/config"
}

@test "task up succeeds again after task down" {
  ! cluster_exists || fail "precondition: kind cluster $CLUSTER exists; run after task down"
  [ ! -e "$PLATFORM_KUBECONFIG" ] || fail "precondition: isolated kubeconfig $PLATFORM_KUBECONFIG still exists"

  run_task up
  [ "$TASK_STATUS" -eq 0 ] || fail "task up after task down exited $TASK_STATUS:"$'\n'"$(task_log_tail)"

  cluster_exists || fail "task up exited 0 but kind cluster $CLUSTER does not exist"
  assert_isolated_kubeconfig
  assert_applications_converged "$TASK_EXIT_EPOCH" "$STABLE_SECONDS"
}
