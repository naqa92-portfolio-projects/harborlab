#!/usr/bin/env bash
# Creates or converges the harborlab platform, then waits until every ArgoCD Application is stable.
# Secrets (CA key, OpenBao unseal key and root token) stay in git-ignored 0600 files or in-cluster.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER=harborlab
NODE="$CLUSTER-control-plane"
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
LOCAL_DIR="$REPO_ROOT/.local"
CA_DIR="$LOCAL_DIR/ca"
OPENBAO_INIT="$LOCAL_DIR/openbao/init.json"
REPO_URL=https://github.com/naqa92-portfolio-projects/harborlab.git
HARBOR_HOST=harbor.127.0.0.1.nip.io

GATEWAY_API_VERSION=v1.6.1
CILIUM_CHART_VERSION=1.20.2
ARGOCD_CHART_VERSION=10.9.2

STABLE_SECONDS=60
# Margin over STABLE_SECONDS so the stability check still holds when a caller re-reads it after exit.
STABLE_MARGIN_SECONDS=5
CONVERGE_TIMEOUT_SECONDS=1800

# Harbor proxy-cache project per upstream registry (the projects themselves arrive with Harbor).
declare -A MIRRORS=(
  [docker.io]="https://registry-1.docker.io|dockerhub-proxy"
  [quay.io]="https://quay.io|quay-proxy"
  [ghcr.io]="https://ghcr.io|ghcr-proxy"
  [registry.k8s.io]="https://registry.k8s.io|k8s-proxy"
  [dhi.io]="https://dhi.io|dhi-proxy"
)

export KUBECONFIG="$PLATFORM_KUBECONFIG"

log() { printf '==> %s\n' "$*" >&2; }
die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

ensure_ca() {
  if [ -s "$CA_DIR/ca.crt" ] && [ -s "$CA_DIR/ca.key" ]; then
    log "local CA already exists"
    return
  fi
  log "generating the local CA in $CA_DIR"
  (umask 077 && mkdir -p "$CA_DIR")
  (umask 077 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj "/CN=harborlab local CA" -keyout "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" 2>/dev/null)
  chmod 600 "$CA_DIR/ca.key" "$CA_DIR/ca.crt"
}

ensure_cluster() {
  (umask 077 && mkdir -p "$(dirname "$PLATFORM_KUBECONFIG")")
  if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    log "kind cluster $CLUSTER already exists"
  else
    log "creating kind cluster $CLUSTER"
    rm -f "$PLATFORM_KUBECONFIG"
    kind create cluster --config "$REPO_ROOT/platform/kind/cluster.yaml" --kubeconfig "$PLATFORM_KUBECONFIG"
  fi
  (umask 077 && kind get kubeconfig --name "$CLUSTER" >"$PLATFORM_KUBECONFIG.tmp")
  mv "$PLATFORM_KUBECONFIG.tmp" "$PLATFORM_KUBECONFIG"
  chmod 600 "$PLATFORM_KUBECONFIG"
}

# containerd pulls every upstream through its Harbor proxy cache and falls back upstream when
# Harbor does not answer or has no such project (refused, TLS error or 404 all move to the next host).
ensure_node_mirrors() {
  log "configuring containerd mirrors on $NODE"
  docker exec -i "$NODE" sh -c "grep -q ' $HARBOR_HOST\$' /etc/hosts || echo '127.0.0.1 $HARBOR_HOST' >>/etc/hosts"
  docker exec -i "$NODE" mkdir -p "/etc/containerd/certs.d/$HARBOR_HOST"
  docker exec -i "$NODE" sh -c "cat >/etc/containerd/certs.d/$HARBOR_HOST/ca.crt" <"$CA_DIR/ca.crt"
  docker exec -i "$NODE" sh -c "cat >/etc/containerd/certs.d/$HARBOR_HOST/hosts.toml" <<EOF
server = "https://$HARBOR_HOST"

[host."https://$HARBOR_HOST"]
  capabilities = ["pull", "resolve"]
  ca = "/etc/containerd/certs.d/$HARBOR_HOST/ca.crt"
EOF
  local registry upstream project
  for registry in "${!MIRRORS[@]}"; do
    upstream="${MIRRORS[$registry]%|*}"
    project="${MIRRORS[$registry]#*|}"
    docker exec -i "$NODE" mkdir -p "/etc/containerd/certs.d/$registry"
    docker exec -i "$NODE" sh -c "cat >/etc/containerd/certs.d/$registry/hosts.toml" <<EOF
server = "$upstream"

[host."https://$HARBOR_HOST/v2/$project"]
  capabilities = ["pull", "resolve"]
  ca = "/etc/containerd/certs.d/$HARBOR_HOST/ca.crt"
  override_path = true
EOF
  done
}

ensure_cilium() {
  log "applying Gateway API $GATEWAY_API_VERSION CRDs"
  kubectl apply --server-side --force-conflicts -f \
    "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml" >/dev/null
  log "installing Cilium chart $CILIUM_CHART_VERSION"
  helm upgrade --install cilium cilium --repo https://helm.cilium.io --version "$CILIUM_CHART_VERSION" \
    --namespace cilium --create-namespace --values "$REPO_ROOT/platform/bootstrap/cilium-values.yaml" \
    --wait --timeout 10m >/dev/null
  kubectl wait node --all --for=condition=Ready --timeout=300s >/dev/null
}

ensure_argocd() {
  log "installing Argo CD chart $ARGOCD_CHART_VERSION"
  helm upgrade --install argocd argo-cd --repo https://argoproj.github.io/argo-helm \
    --version "$ARGOCD_CHART_VERSION" --namespace argocd --create-namespace \
    --values "$REPO_ROOT/platform/bootstrap/argocd-values.yaml" --wait --timeout 10m >/dev/null
}

ensure_root_application() {
  local revision
  revision="${HARBORLAB_REVISION:-$(git -C "$REPO_ROOT" symbolic-ref -q --short HEAD || git -C "$REPO_ROOT" rev-parse HEAD)}"
  if [ "$(git -C "$REPO_ROOT" ls-remote origin "refs/heads/$revision" 2>/dev/null | cut -f1)" != "$(git -C "$REPO_ROOT" rev-parse HEAD)" ]; then
    log "WARNING: Argo CD syncs $REPO_URL@$revision, which differs from the local HEAD (push it first)"
  fi
  log "applying the root Application at revision $revision"
  kubectl apply -f - >/dev/null <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: root
  namespace: argocd
spec:
  project: default
  destination:
    server: https://kubernetes.default.svc
    namespace: argocd
  source:
    repoURL: $REPO_URL
    targetRevision: $revision
    path: platform/apps
    helm:
      valuesObject:
        repoURL: $REPO_URL
        revision: $revision
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    retry:
      limit: 30
      backoff:
        duration: 10s
        factor: 2
        maxDuration: 1m
EOF
}

bao_exec() {
  kubectl -n openbao exec -i openbao-0 -c openbao -- "$@"
}

# Exit code of `bao status`: 0 unsealed, 2 sealed, anything else unreachable.
openbao_status() {
  local code=0
  bao_exec bao status -format=json >"$WORK/bao-status.json" 2>/dev/null || code=$?
  return "$code"
}

# Runs a shell script in the OpenBao container with the root token on stdin (never in argv or output).
bao_root() {
  local script="$1"
  shift
  { jq -r .root_token "$OPENBAO_INIT"; cat; } |
    bao_exec sh -ec 'read -r BAO_TOKEN; export BAO_TOKEN; '"$script" sh "$@"
}

ensure_openbao() {
  log "waiting for the OpenBao server pod"
  local code
  for _ in $(seq 1 120); do
    code=0
    openbao_status || code=$?
    [ "$code" -eq 0 ] || [ "$code" -eq 2 ] && break
    sleep 5
  done
  [ "$code" -eq 0 ] || [ "$code" -eq 2 ] || die "OpenBao server openbao/openbao-0 is not reachable"

  if [ "$(jq -r .initialized "$WORK/bao-status.json")" != true ]; then
    log "initialising OpenBao (keys stored in $OPENBAO_INIT)"
    (umask 077 && mkdir -p "$(dirname "$OPENBAO_INIT")")
    (umask 077 && bao_exec bao operator init -key-shares=1 -key-threshold=1 -format=json >"$OPENBAO_INIT.tmp")
    mv "$OPENBAO_INIT.tmp" "$OPENBAO_INIT"
  fi
  [ -s "$OPENBAO_INIT" ] || die "OpenBao is initialised but $OPENBAO_INIT is missing; run task down then task up"

  if openbao_status; then
    log "OpenBao already unsealed"
  else
    log "unsealing OpenBao"
    jq -r '.unseal_keys_b64[0]' "$OPENBAO_INIT" | bao_exec bao write -format=json sys/unseal key=- >/dev/null
    openbao_status || die "OpenBao is still sealed after unseal"
  fi

  log "configuring OpenBao KV v2, Kubernetes auth, policies and roles"
  bao_root '
    bao secrets list -format=json | grep -q "\"secret/\"" || bao secrets enable -path=secret -version=2 kv >/dev/null
    bao auth list -format=json | grep -q "\"kubernetes/\"" || bao auth enable kubernetes >/dev/null
    bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc:443 >/dev/null
    printf "%s\n" "path \"secret/data/platform/*\" { capabilities = [\"read\"] }" \
      "path \"sys/mounts\" { capabilities = [\"read\"] }" >/tmp/platform-audit.hcl
    bao policy write platform-audit /tmp/platform-audit.hcl >/dev/null
    printf "%s\n" "path \"secret/data/platform/*\" { capabilities = [\"read\"] }" >/tmp/external-secrets.hcl
    bao policy write external-secrets /tmp/external-secrets.hcl >/dev/null
    rm -f /tmp/platform-audit.hcl /tmp/external-secrets.hcl
    bao write auth/kubernetes/role/platform-audit bound_service_account_names=platform-audit \
      bound_service_account_namespaces=openbao token_policies=platform-audit token_ttl=15m >/dev/null
    bao write auth/kubernetes/role/external-secrets bound_service_account_names=openbao-reader \
      bound_service_account_namespaces=external-secrets token_policies=external-secrets token_ttl=15m >/dev/null
  ' </dev/null

  log "seeding the local CA into OpenBao secret/platform/local-ca"
  jq -n --rawfile crt "$CA_DIR/ca.crt" --rawfile key "$CA_DIR/ca.key" '{"tls.crt": $crt, "tls.key": $key}' |
    bao_root 'bao kv put -mount=secret platform/local-ca - >/dev/null'
}

# Exits once every Application has been Synced and Healthy, with a succeeded last sync, for
# STABLE_SECONDS; the timestamps are the ones Argo CD persists in each Application.
wait_for_convergence() {
  log "waiting for every Argo CD Application to be Synced and Healthy for ${STABLE_SECONDS}s"
  local deadline=$((SECONDS + CONVERGE_TIMEOUT_SECONDS)) next_report=$((SECONDS + 60)) pending
  while :; do
    if kubectl get applications.argoproj.io -A -o json >"$WORK/applications.json" 2>/dev/null; then
      pending="$(jq -r --argjson now "$(date -u +%s)" --argjson age "$((STABLE_SECONDS + STABLE_MARGIN_SECONDS))" '
        if (.items | length) == 0 then "no Application yet" else
        .items[]
        | (.status.health.lastTransitionTime // "") as $healthy_since
        | (.status.operationState.finishedAt // "") as $synced_at
        | select(.status.sync.status != "Synced" or .status.health.status != "Healthy"
            or .status.operationState.phase != "Succeeded"
            or $healthy_since == "" or $synced_at == ""
            or ($now - ($healthy_since | fromdateiso8601)) < $age
            or ($now - ($synced_at | fromdateiso8601)) < $age)
        | "\(.metadata.name): sync=\(.status.sync.status) health=\(.status.health.status) operation=\(.status.operationState.phase // "none")"
        end' "$WORK/applications.json")"
      if [ -z "$pending" ]; then
        log "every Argo CD Application is Synced and Healthy"
        return
      fi
    else
      pending="cannot list Applications"
    fi
    if [ "$SECONDS" -ge "$next_report" ]; then
      log "still waiting on:"$'\n'"$pending"
      next_report=$((SECONDS + 60))
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      die "Argo CD Applications did not converge within ${CONVERGE_TIMEOUT_SECONDS}s:"$'\n'"$pending"
    fi
    sleep 10
  done
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

ensure_ca
ensure_cluster
ensure_node_mirrors
ensure_cilium
ensure_argocd
ensure_root_application
ensure_openbao
wait_for_convergence
log "platform ready (kubeconfig: $PLATFORM_KUBECONFIG)"
