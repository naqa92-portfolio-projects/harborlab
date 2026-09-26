#!/usr/bin/env bash
# Deletes the harborlab kind cluster, its isolated kubeconfig and the OpenBao keys bound to it.
# The local CA is kept so that hosts trusting it keep doing so; the caller's kubeconfig is untouched.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER=harborlab
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind delete cluster --name "$CLUSTER" --kubeconfig "$WORK/kubeconfig"
else
  printf '==> kind cluster %s does not exist\n' "$CLUSTER" >&2
fi
rm -f "$PLATFORM_KUBECONFIG"
rm -rf "$REPO_ROOT/.local/openbao"
