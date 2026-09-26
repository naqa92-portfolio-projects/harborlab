#!/usr/bin/env bash
# Deletes the M0 spike kind cluster; the caller's kubeconfig is never touched.
set -euo pipefail

CLUSTER=harborlab-spike
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if kind get clusters | grep -qx "$CLUSTER"; then
  kind delete cluster --name "$CLUSTER" --kubeconfig "$WORK/kubeconfig"
else
  printf '==> kind cluster %s does not exist\n' "$CLUSTER" >&2
fi
