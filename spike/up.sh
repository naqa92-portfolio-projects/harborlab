#!/usr/bin/env bash
# Creates or converges the M0 spike: kind + Harbor (proxy cache, GHCR replication) + Kyverno.
# Secrets (Harbor admin password, TLS key) are generated in-cluster and never printed.
set -euo pipefail

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER=harborlab-spike
NODE="$CLUSTER-control-plane"
HARBOR_HOST=harbor.127.0.0.1.nip.io
HARBOR_CHART_VERSION=1.19.2
KYVERNO_CHART_VERSION=3.9.1
GHCR_REPOSITORY=naqa92-portfolio-projects/harborlab/spike/hello
UNSIGNED_SOURCE=docker.io/library/busybox:1.36.1
SYSTEM_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"
export KUBECONFIG="$WORK/kubeconfig"

log() { printf '==> %s\n' "$*" >&2; }
die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

ensure_cluster() {
  if kind get clusters | grep -qx "$CLUSTER"; then
    log "kind cluster $CLUSTER already exists"
  else
    log "creating kind cluster $CLUSTER"
    kind create cluster --config "$SPIKE_DIR/kind.yaml" --kubeconfig "$KUBECONFIG" --wait 120s
  fi
  (umask 077 && kind get kubeconfig --name "$CLUSTER" >"$KUBECONFIG")
}

secret_key() {
  kubectl -n "$1" get secret "$2" -o jsonpath="{.data.${3//./\\.}}" 2>/dev/null | base64 -d
}

ensure_tls() {
  kubectl create namespace harbor --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  if [ -n "$(secret_key harbor harbor-ca ca.crt)" ] && [ -n "$(secret_key harbor harbor-tls tls.crt)" ]; then
    log "Harbor CA and TLS secrets already exist"
  else
    log "generating the spike CA and Harbor server certificate"
    local d="$WORK/tls"
    (umask 077 && mkdir -p "$d")
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
      -subj "/CN=harborlab spike CA" -keyout "$d/ca.key" -out "$d/ca.crt" 2>/dev/null
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=$HARBOR_HOST" -keyout "$d/tls.key" -out "$d/tls.csr" 2>/dev/null
    printf 'subjectAltName=DNS:%s,DNS:harbor.harbor.svc.cluster.local\nextendedKeyUsage=serverAuth\n' \
      "$HARBOR_HOST" >"$d/ext.cnf"
    openssl x509 -req -in "$d/tls.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" -CAcreateserial \
      -days 365 -extfile "$d/ext.cnf" -out "$d/tls.crt" 2>/dev/null
    kubectl -n harbor create secret generic harbor-ca --from-file=ca.crt="$d/ca.crt" \
      --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    kubectl -n harbor create secret generic harbor-tls --type=kubernetes.io/tls \
      --from-file=tls.crt="$d/tls.crt" --from-file=tls.key="$d/tls.key" --from-file=ca.crt="$d/ca.crt" \
      --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    rm -rf "$d"
  fi
  HARBOR_CA="$WORK/harbor-ca.crt"
  secret_key harbor harbor-ca ca.crt >"$HARBOR_CA"
  [ -s "$HARBOR_CA" ] || die "Secret harbor/harbor-ca has no ca.crt"
}

# In-cluster clients resolve the Harbor host to the Harbor Service instead of 127.0.0.1.
ensure_coredns_rewrite() {
  local rule="rewrite name exact $HARBOR_HOST harbor.harbor.svc.cluster.local"
  if kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}' | grep -qF "$rule"; then
    log "CoreDNS rewrite already in place"
    return
  fi
  log "adding the CoreDNS rewrite for $HARBOR_HOST"
  kubectl -n kube-system get configmap coredns -o json |
    jq --arg rule "$rule" '.data.Corefile |= sub("\n    ready\n"; "\n    ready\n    \($rule)\n")' |
    kubectl apply -f - >/dev/null
  kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}' | grep -qF "$rule" ||
    die "could not insert the CoreDNS rewrite"
  kubectl -n kube-system rollout restart deployment coredns >/dev/null
  kubectl -n kube-system rollout status deployment coredns --timeout=120s >/dev/null
}

ensure_harbor() {
  local password
  password="$(secret_key harbor harbor-core HARBOR_ADMIN_PASSWORD || true)"
  if [ -z "$password" ]; then
    password="$(openssl rand -base64 24 | tr -d '/+=')Aa1"
  fi
  (umask 077 && printf '%s' "$password" | jq -Rs '{harborAdminPassword: .}' >"$WORK/harbor-secret-values.json")
  log "installing Harbor chart $HARBOR_CHART_VERSION"
  helm upgrade --install harbor harbor --repo https://helm.goharbor.io --version "$HARBOR_CHART_VERSION" \
    --namespace harbor --values "$SPIKE_DIR/harbor-values.yaml" --values "$WORK/harbor-secret-values.json" \
    --wait --timeout 15m >/dev/null
  rm -f "$WORK/harbor-secret-values.json"

  log "waiting for https://$HARBOR_HOST"
  for _ in $(seq 1 60); do
    [ "$(curl -sS --max-time 5 --cacert "$HARBOR_CA" "https://$HARBOR_HOST/api/v2.0/ping" 2>/dev/null)" = Pong ] && return
    sleep 5
  done
  die "Harbor does not answer on https://$HARBOR_HOST"
}

# containerd on the node: docker.io goes through the Harbor proxy cache, falls back upstream.
ensure_node_mirror() {
  local cluster_ip
  cluster_ip="$(kubectl -n harbor get service harbor -o jsonpath='{.spec.clusterIP}')"
  [ -n "$cluster_ip" ] || die "Service harbor/harbor has no ClusterIP"
  log "configuring containerd mirrors on $NODE"
  docker exec -i "$NODE" sh -c "grep -v ' $HARBOR_HOST\$' /etc/hosts >/tmp/hosts; echo '$cluster_ip $HARBOR_HOST' >>/tmp/hosts; cat /tmp/hosts >/etc/hosts; rm /tmp/hosts"
  docker exec -i "$NODE" mkdir -p "/etc/containerd/certs.d/$HARBOR_HOST" /etc/containerd/certs.d/docker.io
  docker exec -i "$NODE" sh -c "cat >/etc/containerd/certs.d/$HARBOR_HOST/ca.crt" <"$HARBOR_CA"
  docker exec -i "$NODE" sh -c "cat >/etc/containerd/certs.d/$HARBOR_HOST/hosts.toml" <<EOF
server = "https://$HARBOR_HOST"

[host."https://$HARBOR_HOST"]
  capabilities = ["pull", "resolve"]
  ca = "/etc/containerd/certs.d/$HARBOR_HOST/ca.crt"
EOF
  docker exec -i "$NODE" sh -c "cat >/etc/containerd/certs.d/docker.io/hosts.toml" <<EOF
server = "https://registry-1.docker.io"

[host."https://$HARBOR_HOST/v2/dockerhub-proxy"]
  capabilities = ["pull", "resolve"]
  ca = "/etc/containerd/certs.d/$HARBOR_HOST/ca.crt"
  override_path = true
EOF
}

# Harbor admin API; the Authorization header goes through stdin, the body through a file.
harbor_api() {
  local method="$1" path="$2" body="${3:-}" password
  password="$(secret_key harbor harbor-core HARBOR_ADMIN_PASSWORD)"
  [ -n "$password" ] || die "Secret harbor/harbor-core has no HARBOR_ADMIN_PASSWORD"
  local args=(-sS --cacert "$HARBOR_CA" -H @- -X "$method" -o "$WORK/api-body" -D "$WORK/api-headers"
    -w '%{http_code}')
  if [ -n "$body" ]; then
    printf '%s' "$body" >"$WORK/api-request"
    args+=(-H 'Content-Type: application/json' --data-binary @"$WORK/api-request")
  fi
  printf 'Authorization: Basic %s\n' "$(printf 'admin:%s' "$password" | base64 -w0)" |
    curl "${args[@]}" "https://$HARBOR_HOST/api/v2.0$path"
}

harbor_expect() {
  local expected="$1" code
  shift
  code="$(harbor_api "$@")"
  [[ " $expected " == *" $code "* ]] || die "Harbor API $1 $2 returned HTTP $code: $(head -c 500 "$WORK/api-body")"
}

ensure_registry() {
  local name="$1" type="$2" url="$3"
  harbor_expect 200 GET "/registries?q=name%3D$name"
  if [ "$(jq length "$WORK/api-body")" -eq 0 ]; then
    log "creating Harbor registry endpoint $name"
    harbor_expect 201 POST /registries "$(jq -nc --arg n "$name" --arg t "$type" --arg u "$url" \
      '{name: $n, type: $t, url: $u, insecure: false}')"
    harbor_expect 200 GET "/registries?q=name%3D$name"
  fi
  jq -r '.[0].id' "$WORK/api-body"
}

ensure_project() {
  local name="$1" registry_id="${2:-}" body
  body="$(jq -nc --arg n "$name" '{project_name: $n, metadata: {public: "true"}}')"
  if [ -n "$registry_id" ]; then
    body="$(jq -c --argjson r "$registry_id" '. + {registry_id: $r}' <<<"$body")"
  fi
  if [ "$(harbor_api GET "/projects/$name")" = 200 ]; then
    log "Harbor project $name already exists"
  else
    log "creating Harbor project $name"
    harbor_expect 201 POST /projects "$body"
  fi
}

# Pull replication GHCR -> spike/hello: the image tag plus the cosign referrers fallback tag.
ensure_replication() {
  local ghcr_id="$1" body id execution status
  body="$(jq -nc --argjson r "$ghcr_id" --arg repo "$GHCR_REPOSITORY" '{
    name: "spike-hello-from-ghcr",
    src_registry: {id: $r},
    dest_namespace: "spike",
    dest_namespace_replace_count: -1,
    filters: [{type: "name", value: $repo}, {type: "tag", value: "{m0,sha256-*}"}],
    trigger: {type: "manual"},
    override: true,
    enabled: true
  }')"
  harbor_expect 200 GET "/replication/policies?name=spike-hello-from-ghcr"
  id="$(jq -r '.[0].id // empty' "$WORK/api-body")"
  if [ -z "$id" ]; then
    log "creating replication policy spike-hello-from-ghcr"
    harbor_expect 201 POST /replication/policies "$body"
    harbor_expect 200 GET "/replication/policies?name=spike-hello-from-ghcr"
    id="$(jq -r '.[0].id' "$WORK/api-body")"
  else
    harbor_expect 200 PUT "/replication/policies/$id" "$body"
  fi

  log "running replication policy $id"
  harbor_expect 201 POST /replication/executions "$(jq -nc --argjson p "$id" '{policy_id: $p}')"
  execution="$(tr -d '\r' <"$WORK/api-headers" | awk -F/ 'tolower($0) ~ /^location:/ {print $NF}')"
  [ -n "$execution" ] || die "replication execution id not returned"
  for _ in $(seq 1 120); do
    harbor_expect 200 GET "/replication/executions/$execution"
    status="$(jq -r .status "$WORK/api-body")"
    case "$status" in
    Succeed) return ;;
    Failed | Stopped) die "replication execution $execution ended with status $status: $(jq -c . "$WORK/api-body")" ;;
    esac
    sleep 5
  done
  die "replication execution $execution did not finish"
}

ensure_unsigned_image() {
  if [ "$(harbor_api GET /projects/spike/repositories/unsigned/artifacts/m0)" = 200 ]; then
    log "spike/unsigned:m0 already in Harbor"
    return
  fi
  log "pushing the unsigned image spike/unsigned:m0"
  export DOCKER_CONFIG="$WORK/docker"
  mkdir -p "$DOCKER_CONFIG"
  cat "$SYSTEM_CA_BUNDLE" "$HARBOR_CA" >"$WORK/ca-bundle.crt"
  secret_key harbor harbor-core HARBOR_ADMIN_PASSWORD |
    SSL_CERT_FILE="$WORK/ca-bundle.crt" crane auth login "$HARBOR_HOST" -u admin --password-stdin >/dev/null 2>&1 ||
    die "crane login to $HARBOR_HOST failed"
  SSL_CERT_FILE="$WORK/ca-bundle.crt" crane copy --platform linux/amd64 "$UNSIGNED_SOURCE" "$HARBOR_HOST/spike/unsigned:m0"
  rm -rf "$DOCKER_CONFIG"
  unset DOCKER_CONFIG
}

ensure_kyverno() {
  log "installing Kyverno chart $KYVERNO_CHART_VERSION"
  kubectl create namespace kyverno --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n kyverno create configmap harbor-ca --from-file=harbor-ca.crt="$HARBOR_CA" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  helm upgrade --install kyverno kyverno --repo https://kyverno.github.io/kyverno --version "$KYVERNO_CHART_VERSION" \
    --namespace kyverno --values "$SPIKE_DIR/kyverno-values.yaml" --wait --timeout 10m >/dev/null

  log "applying ImageValidatingPolicy spike-verify-harbor"
  for _ in $(seq 1 30); do
    kubectl apply -f "$SPIKE_DIR/policy.yaml" >/dev/null 2>&1 && break
    sleep 5
  done
  kubectl get imagevalidatingpolicies.policies.kyverno.io spike-verify-harbor >/dev/null
  for _ in $(seq 1 60); do
    [ "$(kubectl get imagevalidatingpolicies.policies.kyverno.io spike-verify-harbor \
      -o jsonpath='{.status.conditionStatus.ready}')" = true ] && return
    sleep 5
  done
  die "ImageValidatingPolicy spike-verify-harbor is not ready"
}

ensure_cluster
ensure_tls
ensure_coredns_rewrite
ensure_harbor
ensure_node_mirror
ghcr_registry_id="$(ensure_registry ghcr github-ghcr https://ghcr.io)"
dockerhub_registry_id="$(ensure_registry docker-hub docker-hub https://hub.docker.com)"
ensure_project spike
ensure_project dockerhub-proxy "$dockerhub_registry_id"
ensure_replication "$ghcr_registry_id"
ensure_unsigned_image
ensure_kyverno
log "spike ready: https://$HARBOR_HOST"
