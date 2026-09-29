#!/usr/bin/env bash
# Runs a shell non-interactively in the runtime-demo workload container once Kubescape node-agent has
# loaded the container's authored profile, then waits for the "Unexpected process launched" alert it
# raises and prints it. Exits non-zero when node-agent never loads the profile or no alert comes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE=runtime-demo
DEPLOYMENT=runtime-demo
CONTAINER=runtime-demo
NODE_AGENT=kubescape/node-agent
VICTORIALOGS_QUERY=/api/v1/namespaces/observability/services/victoria-logs:http/proxy/select/logsql/query
# node-agent's info line once a container's user-defined ContainerProfile is in its rule cache; a failed
# profile fetch is retried on node-agent's one-minute reconcile tick.
PROFILE_LOADED_MESSAGE='adopted user-authored ContainerProfile as authoritative base'
PROFILE_TIMEOUT_SECONDS=90
# Criterion 20 budget: an alert within 2 minutes of the first shell. After the adoption log, node-agent's
# rule manager binds the pod on its own backoff poll (up to ~1 s later, no info-level signal) and drops the
# exec events before that: a shell left without alert is followed by a new shell process.
ALERT_BUDGET_SECONDS=120
SHELL_ALERT_WAIT_SECONDS=10
POLL_SECONDS=2

export KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[ -s "$KUBECONFIG" ] || die "platform is not up: $KUBECONFIG missing (run task up)"

# node-agent log entries (JSON lines) since $1.
node_agent_logs() {
  kubectl -n "${NODE_AGENT%/*}" logs "daemonset/${NODE_AGENT#*/}" -c node-agent --since-time="$1" |
    jq -c 'fromjson? // empty' -R
}

# Whether node-agent logged the profile adoption of container $1 since $2: its current log first, then
# VictoriaLogs, which keeps node-agent logs rotated away since.
profile_loaded() {
  node_agent_logs "$2" | jq -e --arg m "$PROFILE_LOADED_MESSAGE" --arg c "$1" \
    'select(.msg == $m and .containerID == $c)' >/dev/null && return 0
  kubectl get --raw "$VICTORIALOGS_QUERY?query=$(jq -rn --arg q "_time:>=$2 \"$PROFILE_LOADED_MESSAGE\" containerID:=\"$1\"" \
    '$q | @uri')&limit=1" | grep -q .
}

target="$(kubectl -n "$NAMESPACE" get pods -l "app.kubernetes.io/name=$DEPLOYMENT" -o json | jq -r --arg c "$CONTAINER" '
  [.items[] | select(.metadata.deletionTimestamp == null)
    | .metadata.name as $pod | .status.containerStatuses[]?
    | select(.name == $c and .ready and .state.running != null)
    | "\($pod) \(.containerID | sub("^[a-z]+://"; "")) \(.state.running.startedAt)"] | .[0] // empty')"
[ -n "$target" ] || die "no running pod of deployment $NAMESPACE/$DEPLOYMENT"
read -r pod container_id started_at <<<"$target"

# Rules that compare behaviour with a profile stay silent until node-agent holds this container's profile.
deadline=$((SECONDS + PROFILE_TIMEOUT_SECONDS))
until profile_loaded "$container_id" "$started_at"; do
  [ "$SECONDS" -lt "$deadline" ] ||
    die "node-agent has not loaded the Kubescape profile of $NAMESPACE/$pod/$CONTAINER after ${PROFILE_TIMEOUT_SECONDS}s"
  sleep "$POLL_SECONDS"
done

# node-agent's R0001 alert on a shell of this container since $1, empty when none.
shell_alert() {
  node_agent_logs "$1" | jq -r --arg ns "$NAMESPACE" --arg pod "$pod" --arg c "$CONTAINER" '
    select(.RuleID == "R0001" and .RuntimeK8sDetails.namespace == $ns and .RuntimeK8sDetails.podName == $pod
      and .RuntimeK8sDetails.containerName == $c and .RuntimeProcessDetails.processTree.comm == "sh")
    | "\(.BaseRuntimeMetadata.alertName): \(.RuntimeProcessDetails.processTree.cmdline)"' | head -n 1
}

exec_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "runtime-shell target: $NAMESPACE/$pod/$CONTAINER"
budget_end=$((SECONDS + ALERT_BUDGET_SECONDS))
shells=0
alert=""
while [ -z "$alert" ]; do
  [ "$SECONDS" -lt "$budget_end" ] ||
    die "Kubescape raised no alert for $shells shell(s) in $NAMESPACE/$pod/$CONTAINER within ${ALERT_BUDGET_SECONDS}s"
  [ "$shells" -eq 0 ] ||
    echo "no alert ${SHELL_ALERT_WAIT_SECONDS}s after shell $shells (node-agent had not bound the pod yet): running a new shell"
  shells=$((shells + 1))
  kubectl -n "$NAMESPACE" exec "$pod" -c "$CONTAINER" -- sh -c 'echo "shell ran in $HOSTNAME"'
  deadline=$((SECONDS + SHELL_ALERT_WAIT_SECONDS))
  while [ -z "$alert" ] && [ "$SECONDS" -lt "$deadline" ]; do
    sleep "$POLL_SECONDS"
    alert="$(shell_alert "$exec_time")"
  done
done
echo "runtime-shell alert: $alert"
