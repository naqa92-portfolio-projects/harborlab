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
DT_HOST=dependency-track.127.0.0.1.nip.io
# Least privilege of the dt-bridge API key: upload BOM and VEX, read findings; no portfolio management.
DT_BRIDGE_PERMISSIONS=(BOM_UPLOAD PROJECT_CREATION_UPLOAD VIEW_PORTFOLIO VIEW_VULNERABILITY VULNERABILITY_ANALYSIS)
DT_OSV_ECOSYSTEMS='["Debian:13", "PyPI", "Maven"]'

GATEWAY_API_VERSION=v1.6.1
CILIUM_CHART_VERSION=1.20.2
ARGOCD_CHART_VERSION=10.9.2

# Applications running images of Harbor `apps`: they converge only once Harbor has replicated them.
WORKLOAD_APPLICATIONS='["dt-bridge", "hello-java", "runtime-demo"]'
GOVERNED_REPLICATIONS=(golden-from-ghcr apps-from-ghcr apps-demo-from-ghcr)
REPLICATION_TIMEOUT_SECONDS=900

# External Secrets consumers: "<namespace>|<OpenBao KV paths under secret/ it may read>". Each namespace
# authenticates as its own ServiceAccount openbao-reader and gets an OpenBao policy for these paths only.
ESO_CONSUMERS=(
  "cert-manager|platform/local-ca"
  "harbor|platform/harbor-admin platform/harbor-db platform/harbor-registry platform/harbor-internal platform/harbor-token-service"
  "dependency-track|platform/dependency-track-db"
  "dt-bridge|platform/harbor-robot-dt-bridge platform/dependency-track-api-key platform/dhi platform/harbor-webhook-dt-bridge"
  "observability|platform/grafana-admin"
  "registry-mirror-test|platform/dhi"
)

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

# Strict X.509 clients (Python VERIFY_X509_STRICT) reject a CA without a critical keyUsage: a CA
# generated before it carried one is replaced, and CA_REGENERATED tells task up to re-roll its consumers.
CA_REGENERATED=false
ensure_ca() {
  if [ -s "$CA_DIR/ca.crt" ] && [ -s "$CA_DIR/ca.key" ]; then
    if openssl x509 -in "$CA_DIR/ca.crt" -noout -text | grep -A1 'X509v3 Key Usage: critical' |
      grep -q 'Certificate Sign, CRL Sign'; then
      log "local CA already exists"
      return
    fi
    log "the local CA has no critical keyUsage keyCertSign, cRLSign: regenerating it"
    CA_REGENERATED=true
  fi
  log "generating the local CA in $CA_DIR"
  (umask 077 && mkdir -p "$CA_DIR")
  (umask 077 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj "/CN=harborlab local CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" 2>/dev/null)
  chmod 600 "$CA_DIR/ca.key" "$CA_DIR/ca.crt"
}

# After a CA regeneration on an existing cluster: cert-manager gets the new key pair, re-issues the
# certificates it signed, and the workloads that load the trust bundles at start are restarted.
reroll_ca_consumers() {
  [ "$CA_REGENERATED" = true ] || return 0
  kubectl -n cert-manager get externalsecret harborlab-ca >/dev/null 2>&1 || return 0
  log "re-rolling the consumers of the regenerated local CA"
  kubectl -n cert-manager annotate externalsecret harborlab-ca --overwrite "force-sync=$(date +%s)" >/dev/null
  local expected deadline=$((SECONDS + 120))
  expected="$(base64 -w0 <"$CA_DIR/ca.crt")"
  until [ "$(kubectl -n cert-manager get secret harborlab-ca -o jsonpath='{.data.tls\.crt}' 2>/dev/null)" = "$expected" ]; do
    [ "$SECONDS" -lt "$deadline" ] || die "Secret cert-manager/harborlab-ca does not hold the regenerated CA after 120s"
    sleep 5
  done
  kubectl get certificates.cert-manager.io -A -o json |
    jq -r '.items[] | select(.spec.issuerRef.kind == "ClusterIssuer" and .spec.issuerRef.name == "harborlab-ca")
      | "\(.metadata.namespace) \(.spec.secretName)"' |
    while read -r namespace secret; do
      kubectl -n "$namespace" delete secret "$secret" --ignore-not-found >/dev/null
    done
  sleep 30
  kubectl get deployments,statefulsets,daemonsets -A -o json |
    jq -r '.items[] | select(any(.spec.template.spec.volumes[]?;
        (.configMap.name // "") | test("harborlab"))
      or any(.spec.template.spec.volumes[]?.projected.sources[]?; (.configMap.name // "") | test("harborlab")))
      | "\(.metadata.namespace) \(.kind | ascii_downcase)/\(.metadata.name)"' |
    while read -r namespace workload; do
      kubectl -n "$namespace" rollout restart "$workload" >/dev/null
    done
}

ensure_cluster() {
  (umask 077 && mkdir -p "$(dirname "$PLATFORM_KUBECONFIG")")
  if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    log "kind cluster $CLUSTER already exists"
  else
    log "creating kind cluster $CLUSTER"
    rm -f "$PLATFORM_KUBECONFIG"
    (cd "$REPO_ROOT" && kind create cluster --config platform/kind/cluster.yaml --kubeconfig "$PLATFORM_KUBECONFIG")
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
    # A leftover OpenTofu state is encrypted with the Transit key of a previous OpenBao.
    rm -f "$REPO_ROOT/tofu/harbor/terraform.tfstate" "$REPO_ROOT/tofu/harbor/terraform.tfstate.backup"
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
    printf "%s\n" "path \"secret/metadata/platform/*\" { capabilities = [\"read\"] }" \
      "path \"sys/mounts\" { capabilities = [\"read\"] }" >/tmp/platform-audit.hcl
    bao policy write platform-audit /tmp/platform-audit.hcl >/dev/null
    rm -f /tmp/platform-audit.hcl
    bao write auth/kubernetes/role/platform-audit bound_service_account_names=platform-audit \
      bound_service_account_namespaces=openbao token_policies=platform-audit token_ttl=15m >/dev/null
    bao secrets list -format=json | grep -q "\"transit/\"" || bao secrets enable -path=transit transit >/dev/null
    bao read transit/keys/harbor-tofu-state >/dev/null 2>&1 || bao write -f transit/keys/harbor-tofu-state >/dev/null
    printf "%s\n" "path \"transit/datakey/plaintext/harbor-tofu-state\" { capabilities = [\"update\"] }" \
      "path \"transit/decrypt/harbor-tofu-state\" { capabilities = [\"update\"] }" \
      "path \"secret/data/platform/harbor-admin\" { capabilities = [\"read\"] }" \
      "path \"secret/data/platform/harbor-robot-dt-bridge\" { capabilities = [\"read\"] }" \
      "path \"secret/data/platform/dhi\" { capabilities = [\"read\"] }" \
      "path \"secret/data/platform/harbor-webhook-dt-bridge\" { capabilities = [\"read\"] }" >/tmp/harbor-tofu.hcl
    bao policy write harbor-tofu /tmp/harbor-tofu.hcl >/dev/null
    rm -f /tmp/harbor-tofu.hcl
    bao write auth/kubernetes/role/harbor-tofu bound_service_account_names=harbor-tofu \
      bound_service_account_namespaces=openbao token_policies=harbor-tofu token_ttl=15m >/dev/null
  ' </dev/null
  ensure_eso_access

  log "seeding the local CA into OpenBao secret/platform/local-ca"
  jq -n --rawfile crt "$CA_DIR/ca.crt" --rawfile key "$CA_DIR/ca.key" '{"tls.crt": $crt, "tls.key": $key}' |
    bao_root 'bao kv put -mount=secret platform/local-ca - >/dev/null'
}

# One OpenBao role for External Secrets, bound to the openbao-reader ServiceAccount of each consumer
# namespace and granting nothing itself: the policy of a consumer, scoped to its exact paths, is carried by
# the identity entity its ServiceAccount logs in as (entity alias "<namespace>/openbao-reader").
ensure_eso_access() {
  local accessor entry namespace paths path namespaces=""
  accessor="$(bao_root 'bao auth list -format=json' </dev/null | jq -r '."kubernetes/".accessor')"
  [ -n "$accessor" ] && [ "$accessor" != null ] || die "cannot read the accessor of the OpenBao kubernetes auth mount"
  for entry in "${ESO_CONSUMERS[@]}"; do
    IFS='|' read -r namespace paths <<<"$entry"
    namespaces="${namespaces:+$namespaces,}$namespace"
    for path in $paths; do
      printf 'path "secret/data/%s" { capabilities = ["read"] }\n' "$path"
    done | bao_root 'bao policy write "$1" - >/dev/null' "external-secrets-$namespace"
    bao_root '
      bao write identity/entity/name/external-secrets-"$1" policies=external-secrets-"$1" >/dev/null
      id="$(bao read -field=id identity/entity/name/external-secrets-"$1")"
      if [ -z "$(bao write -format=json identity/lookup/entity alias_name="$1/openbao-reader" alias_mount_accessor="$2")" ]; then
        bao write identity/entity-alias name="$1/openbao-reader" canonical_id="$id" mount_accessor="$2" >/dev/null
      fi
    ' "$namespace" "$accessor" </dev/null
  done
  bao_root '
    bao write auth/kubernetes/role/external-secrets bound_service_account_names=openbao-reader \
      bound_service_account_namespaces="$1" alias_name_source=serviceaccount_name token_policies=default \
      token_ttl=15m >/dev/null
    bao policy delete external-secrets >/dev/null
  ' "$namespaces" </dev/null
}

# Prints one alphanumeric random string per requested length, one per line.
random_strings() {
  local length value
  for length in "$@"; do
    value="$(openssl rand -base64 96 | tr -dc 'A-Za-z0-9')"
    printf '%s\n' "${value:0:$length}"
  done
}

# Writes the JSON object read on stdin to secret/<path> only when the path does not exist yet, so a
# credential is generated once per cluster and never rotated by a later `task up`.
seed_once() {
  bao_root 'bao kv get -mount=secret "$1" >/dev/null 2>&1 </dev/null || bao kv put -mount=secret "$1" - >/dev/null' "$1"
}

openbao_has() {
  bao_root 'bao kv get -mount=secret "$1" >/dev/null 2>&1' "$1" </dev/null 2>/dev/null
}

# Generated values reach jq and OpenBao through pipes only, never through argv.
seed_credentials() {
  log "seeding platform credentials into OpenBao (existing entries are kept)"
  # Harbor requires upper case, lower case and digits in the admin password.
  random_strings 24 | jq -Rn '{password: (input + "Aa1")}' | seed_once platform/harbor-admin
  random_strings 32 | jq -Rn '{username: "harbor", password: input}' | seed_once platform/harbor-db
  random_strings 32 | jq -Rn '{password: input}' | seed_once platform/harbor-registry
  # Lengths required by the chart: 16 for the component and encryption secrets, 32 for CSRF.
  random_strings 16 32 16 16 16 | jq -Rn '[inputs] as $v
    | {secret: $v[0], CSRF_KEY: $v[1], JOBSERVICE_SECRET: $v[2], REGISTRY_HTTP_SECRET: $v[3], secretKey: $v[4]}' |
    seed_once platform/harbor-internal

  if ! openbao_has platform/harbor-token-service; then
    # Harbor core only reads a PKCS#1 ("RSA PRIVATE KEY") token signing key.
    (umask 077 && openssl genrsa -traditional -out "$WORK/token.key" 4096 2>/dev/null &&
      openssl req -x509 -key "$WORK/token.key" -days 3650 -subj "/CN=harbor-token-service" -out "$WORK/token.crt")
    jq -n --rawfile crt "$WORK/token.crt" --rawfile key "$WORK/token.key" '{"tls.crt": $crt, "tls.key": $key}' |
      seed_once platform/harbor-token-service
    rm -f "$WORK/token.key" "$WORK/token.crt"
  fi

  random_strings 32 | jq -Rn '{username: "dtrack", password: input}' | seed_once platform/dependency-track-db
  random_strings 24 | jq -Rn '{password: (input + "Aa1")}' | seed_once platform/dependency-track-admin
  random_strings 24 | jq -Rn '{username: "admin", password: input}' | seed_once platform/grafana-admin

  # The dhi.io credential comes from the environment (git-ignored .env), read by jq.
  if ! openbao_has platform/dhi; then
    [ -n "${DHI_USERNAME:-}" ] && [ -n "${DHI_TOKEN:-}" ] ||
      die "DHI_USERNAME and DHI_TOKEN must be set (git-ignored .env) to seed OpenBao secret/platform/dhi"
    jq -n '{username: env.DHI_USERNAME, token: env.DHI_TOKEN}' | seed_once platform/dhi
  fi
}

# Exits once every Application, except those named in the JSON array $1, has been Synced and Healthy,
# with a succeeded last sync, for STABLE_SECONDS; the timestamps are the ones Argo CD persists.
wait_for_convergence() {
  local excluded="${1:-[]}"
  log "waiting for the Argo CD Applications (excluded: $excluded) to be Synced and Healthy for ${STABLE_SECONDS}s"
  local deadline=$((SECONDS + CONVERGE_TIMEOUT_SECONDS)) next_report=$((SECONDS + 60)) pending
  while :; do
    if kubectl get applications.argoproj.io -A -o json >"$WORK/applications.json" 2>/dev/null; then
      pending="$(jq -r --argjson now "$(date -u +%s)" --argjson age "$((STABLE_SECONDS + STABLE_MARGIN_SECONDS))" \
        --argjson excluded "$excluded" '
        if (.items | length) == 0 then "no Application yet" else
        .items[]
        | select(.metadata.name as $name | $excluded | index($name) | not)
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
        log "the Argo CD Applications are Synced and Healthy"
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

# Runs the governed pull replications now rather than at their schedule and waits for each to
# succeed. The admin credential goes to curl through a 0600 header file, never argv.
replicate_governed_projects() {
  local auth="$WORK/harbor-auth" api="https://$HARBOR_HOST/api/v2.0" replication id execution status deadline
  (umask 077 && kubectl -n harbor get secret harbor-admin -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 -d |
    { printf 'admin:'; cat; } | base64 -w0 | { printf 'Authorization: Basic '; cat; echo; } >"$auth")
  for replication in "${GOVERNED_REPLICATIONS[@]}"; do
    id="$(curl -sS --fail --cacert "$CA_DIR/ca.crt" -H @"$auth" "$api/replication/policies?name=$replication" |
      jq -r --arg n "$replication" '.[] | select(.name == $n) | .id')"
    [ -n "$id" ] || die "Harbor replication policy $replication not found"
    log "running Harbor replication $replication"
    execution="$(curl -sS --fail --cacert "$CA_DIR/ca.crt" -H @"$auth" -H 'Content-Type: application/json' \
      --data "{\"policy_id\": $id}" -D - -o /dev/null "$api/replication/executions" |
      tr -d '\r' | awk 'tolower($1) == "location:" { print $2 }' | sed 's#.*/##')"
    [[ "$execution" =~ ^[0-9]+$ ]] || die "Harbor did not start replication $replication"
    deadline=$((SECONDS + REPLICATION_TIMEOUT_SECONDS))
    while :; do
      status="$(curl -sS --fail --cacert "$CA_DIR/ca.crt" -H @"$auth" "$api/replication/executions/$execution" |
        jq -r '.status // ""')"
      case "$status" in
        Succeed | Success) break ;;
        "" | InProgress | Running | Pending | Scheduled) ;;
        *) die "Harbor replication $replication ended $status" ;;
      esac
      [ "$SECONDS" -lt "$deadline" ] || die "Harbor replication $replication still $status after ${REPLICATION_TIMEOUT_SECONDS}s"
      sleep 10
    done
  done
  rm -f "$auth"
}

# Dependency-Track REST call with the admin session; body and headers stay in 0600 files of $WORK.
# Prints the HTTP status, the response body lands in $WORK/dt-body.json.
dt_admin() {
  local method="$1" path="$2"
  shift 2
  curl -sS --cacert "$CA_DIR/ca.crt" -H @"$WORK/dt-auth" -X "$method" -o "$WORK/dt-body.json" -w '%{http_code}' \
    "$@" "https://$DT_HOST/api$path"
}

# Rotates the default admin password to the one seeded in OpenBao, creates the least-privilege dt-bridge
# team and its API key (written back to OpenBao, never printed) and restricts the vulnerability sources
# to OSV. Idempotent: an API key that still authenticates is kept.
ensure_dependency_track() {
  local api="https://$DT_HOST/api" code team permission
  log "bootstrapping Dependency-Track (admin password, dt-bridge team and API key, vulnerability sources)"
  for _ in $(seq 1 180); do
    curl -sf --cacert "$CA_DIR/ca.crt" -o /dev/null "$api/version" && break
    sleep 10
  done
  curl -sf --cacert "$CA_DIR/ca.crt" -o /dev/null "$api/version" || die "Dependency-Track API $api is not reachable"

  (umask 077 && bao_root 'bao kv get -mount=secret -field=password platform/dependency-track-admin' </dev/null |
    jq -Rr '@uri' >"$WORK/dt-admin")
  [ -s "$WORK/dt-admin" ] || die "OpenBao secret/platform/dependency-track-admin has no password"
  (umask 077 && { printf 'username=admin&password=admin&newPassword='; tr -d '\n' <"$WORK/dt-admin"
    printf '&confirmPassword='; tr -d '\n' <"$WORK/dt-admin"; } >"$WORK/dt-force")
  code="$(curl -sS --cacert "$CA_DIR/ca.crt" -o /dev/null -w '%{http_code}' --data @"$WORK/dt-force" \
    "$api/v1/user/forceChangePassword")"
  case "$code" in
    200) log "Dependency-Track admin password rotated from OpenBao" ;;
    401) ;;
    *) die "Dependency-Track admin password rotation failed (HTTP $code)" ;;
  esac
  (umask 077 && { printf 'username=admin&password='; tr -d '\n' <"$WORK/dt-admin"; } >"$WORK/dt-login")
  (umask 077 && curl -sS --fail --cacert "$CA_DIR/ca.crt" --data @"$WORK/dt-login" "$api/v1/user/login" |
    { printf 'Authorization: Bearer '; cat; echo; } >"$WORK/dt-auth") ||
    die "Dependency-Track admin login with the OpenBao password failed"
  rm -f "$WORK/dt-admin" "$WORK/dt-force" "$WORK/dt-login"

  code="$(dt_admin GET /v1/team)"
  [ "$code" = 200 ] || die "cannot list Dependency-Track teams (HTTP $code)"
  team="$(jq -r '.[] | select(.name == "dt-bridge") | .uuid' "$WORK/dt-body.json")"
  if [ -z "$team" ]; then
    code="$(dt_admin PUT /v1/team -H 'Content-Type: application/json' --data '{"name": "dt-bridge"}')"
    [ "$code" = 201 ] || die "cannot create the Dependency-Track team dt-bridge (HTTP $code)"
    team="$(jq -r .uuid "$WORK/dt-body.json")"
  fi
  for permission in "${DT_BRIDGE_PERMISSIONS[@]}"; do
    code="$(dt_admin POST "/v1/permission/$permission/team/$team")"
    case "$code" in
      200 | 304) ;;
      *) die "cannot grant $permission to the Dependency-Track team dt-bridge (HTTP $code)" ;;
    esac
  done

  code=000
  if openbao_has platform/dependency-track-api-key; then
    code="$(bao_root 'bao kv get -mount=secret -field=api-key platform/dependency-track-api-key' </dev/null |
      { printf 'X-Api-Key: '; cat; echo; } |
      curl -sS --cacert "$CA_DIR/ca.crt" -H @- -o /dev/null -w '%{http_code}' "$api/v1/team/self")"
  fi
  if [ "$code" != 200 ]; then
    log "creating the dt-bridge API key into OpenBao secret/platform/dependency-track-api-key"
    code="$(dt_admin PUT "/v1/team/$team/key")"
    [ "$code" = 201 ] || die "cannot create the dt-bridge API key (HTTP $code)"
    jq '{"api-key": .key}' "$WORK/dt-body.json" |
      bao_root 'bao kv put -mount=secret platform/dependency-track-api-key - >/dev/null'
    rm -f "$WORK/dt-body.json"
    kubectl -n dt-bridge annotate externalsecret dependency-track-api-key --overwrite \
      "force-sync=$(date +%s)" >/dev/null 2>&1 || true
  fi

  # OSV only (Debian 13, PyPI, Maven, GitHub advisories through OSV aliases): no NVD mirror.
  code="$(dt_admin PUT /v2/extension-points/vuln-data-source/extensions/nvd/config \
    -H 'Content-Type: application/json' --data '{"config": {"enabled": false}}')"
  case "$code" in 204 | 304) ;; *) die "cannot disable the NVD data source (HTTP $code)" ;; esac
  code="$(dt_admin PUT /v2/extension-points/vuln-data-source/extensions/osv/config \
    -H 'Content-Type: application/json' --data "$(jq -n --argjson e "$DT_OSV_ECOSYSTEMS" '{config: {enabled: true,
      aliasSyncEnabled: true, incrementalMirroringEnabled: true,
      dataUrl: "https://storage.googleapis.com/osv-vulnerabilities", ecosystems: $e}}')")"
  case "$code" in
    204)
      code="$(dt_admin POST /v2/vuln-data-sources/osv/mirror-runs)"
      case "$code" in 202 | 400 | 409) ;; *) die "cannot start the OSV mirror (HTTP $code)" ;; esac
      ;;
    304) ;;
    *) die "cannot configure the OSV data source (HTTP $code)" ;;
  esac
  rm -f "$WORK/dt-auth" "$WORK/dt-body.json"
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
reroll_ca_consumers
seed_credentials
# Before the first convergence: dt-bridge, a child of root, needs its Harbor robot and DT API key Secrets.
"$REPO_ROOT/scripts/harbor-tofu.sh" seed
ensure_dependency_track
# root aggregates the health of the workload Applications, which wait for the replication below.
wait_for_convergence "$(jq -c '. + ["root"]' <<<"$WORKLOAD_APPLICATIONS")"
"$REPO_ROOT/scripts/harbor-tofu.sh" configure
replicate_governed_projects
wait_for_convergence
log "platform ready (kubeconfig: $PLATFORM_KUBECONFIG)"
