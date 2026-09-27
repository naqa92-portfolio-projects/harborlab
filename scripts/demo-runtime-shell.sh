#!/usr/bin/env bash
# Runs a shell non-interactively in the runtime-demo workload container once Kubescape node-agent has
# loaded the container's authored profile, then waits for the "Unexpected process launched" alert it
# raises and prints it. Exits non-zero when node-agent never loads the profile or no alert comes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE=runtime-demo
DEPLOYMENT=runtime-demo
CONTAINER=runtime-demo
VICTORIALOGS_QUERY=/api/v1/namespaces/observability/services/victoria-logs:http/proxy/select/logsql/query
# node-agent's info line once a container's user-defined ContainerProfile is in its rule cache.
PROFILE_LOADED_MESSAGE='adopted user-authored ContainerProfile as authoritative base'
PROFILE_TIMEOUT_SECONDS=60
ALERT_TIMEOUT_SECONDS=45
POLL_SECONDS=3

export KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[ -s "$KUBECONFIG" ] || die "platform is not up: $KUBECONFIG missing (run task up)"

# VictoriaLogs entries (JSON lines) matching the LogsQL query $1, read through the API server proxy.
logs_query() {
  kubectl get --raw "$VICTORIALOGS_QUERY?query=$(jq -rn --arg q "$1" '$q | @uri')&limit=20"
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
until logs_query "_time:>=$started_at \"$PROFILE_LOADED_MESSAGE\" containerID:=\"$container_id\"" | grep -q .; do
  [ "$SECONDS" -lt "$deadline" ] ||
    die "node-agent has not loaded the Kubescape profile of $NAMESPACE/$pod/$CONTAINER after ${PROFILE_TIMEOUT_SECONDS}s"
  sleep "$POLL_SECONDS"
done

exec_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
kubectl -n "$NAMESPACE" exec "$pod" -c "$CONTAINER" -- sh -c 'echo "shell ran in $HOSTNAME"'
echo "runtime-shell target: $NAMESPACE/$pod/$CONTAINER"

deadline=$((SECONDS + ALERT_TIMEOUT_SECONDS))
while :; do
  alert="$(logs_query "_time:>=$exec_time RuleID:R0001 RuntimeK8sDetails.namespace:=\"$NAMESPACE\" RuntimeK8sDetails.podName:=\"$pod\" RuntimeK8sDetails.containerName:=\"$CONTAINER\"" |
    jq -r 'select(."RuntimeProcessDetails.processTree.comm" == "sh")
      | "\(."BaseRuntimeMetadata.alertName"): \(."RuntimeProcessDetails.processTree.cmdline")"' | head -n 1)"
  [ -z "$alert" ] || break
  [ "$SECONDS" -lt "$deadline" ] ||
    die "Kubescape raised no alert for the shell in $NAMESPACE/$pod/$CONTAINER within ${ALERT_TIMEOUT_SECONDS}s"
  sleep "$POLL_SECONDS"
done
echo "runtime-shell alert: $alert"
