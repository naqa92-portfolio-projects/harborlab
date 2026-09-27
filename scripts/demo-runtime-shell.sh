#!/usr/bin/env bash
# Runs a shell non-interactively in the runtime-demo workload container once Kubescape has closed its
# application profile, so node-agent raises an "Unexpected process launched" alert for it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE=runtime-demo
DEPLOYMENT=runtime-demo
CONTAINER=runtime-demo
PROFILE_TIMEOUT_SECONDS=240

export KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[ -s "$KUBECONFIG" ] || die "platform is not up: $KUBECONFIG missing (run task up)"

pod="$(kubectl -n "$NAMESPACE" get pods -l "app.kubernetes.io/name=$DEPLOYMENT" -o json | jq -r '
  [.items[] | select(.metadata.deletionTimestamp == null)
    | select(any(.status.containerStatuses[]?; .ready and .state.running != null))] | .[0] // empty
  | "\(.metadata.name) \(.metadata.labels["pod-template-hash"] // "")"')"
[ -n "$pod" ] || die "no running pod of deployment $NAMESPACE/$DEPLOYMENT"
read -r pod hash <<<"$pod"

# The profile of this ReplicaSet's container must be closed: a shell run while it learns would join it.
deadline=$((SECONDS + PROFILE_TIMEOUT_SECONDS))
until kubectl -n "$NAMESPACE" get containerprofiles.spdx.softwarecomposition.kubescape.io \
  -l "kubescape.io/workload-name=$DEPLOYMENT,kubescape.io/workload-container-name=$CONTAINER,kubescape.io/instance-template-hash=$hash" \
  -o json | jq -e 'any(.items[]; .metadata.annotations["kubescape.io/status"] == "completed")' >/dev/null; do
  [ "$SECONDS" -lt "$deadline" ] ||
    die "the Kubescape profile of $NAMESPACE/$pod/$CONTAINER is not completed after ${PROFILE_TIMEOUT_SECONDS}s"
  sleep 5
done

kubectl -n "$NAMESPACE" exec "$pod" -c "$CONTAINER" -- sh -c 'echo "shell ran in $HOSTNAME"'
echo "runtime-shell target: $NAMESPACE/$pod/$CONTAINER"
