#!/usr/bin/env bats
# What a tenant (workload) namespace can reach, live against the cluster started by `task up`: platform
# secrets through External Secrets, the shared Gateway and ClusterIssuer, dt-bridge and VictoriaLogs.
# No secret value is ever read: only the existence of Secrets and exit codes are observed.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
TENANT_NAMESPACE=tenant-isolation-test
TIER_LABEL=harborlab.io/tier
SECRET_STORE=openbao
OPENBAO_NAMESPACE=openbao
OPENBAO_POD=openbao-0
AUDIT_ROLE=platform-audit
GATEWAY=gateway/platform
HARBOR_HOST=harbor.127.0.0.1.nip.io
CLUSTER_ISSUER=harborlab-ca
RUNTIME_DEMO=runtime-demo/runtime-demo
DT_BRIDGE_SERVICE=dt-bridge/dt-bridge
VICTORIALOGS_SERVICE=observability/victoria-logs
VICTORIALOGS_PORT=9428
DENIAL_WINDOW_SECONDS=60
# A value that cannot be the webhook's shared secret.
WRONG_SHARED_SECRET=wrong

fail() {
  echo "$*" >&2
  return 1
}

setup_file() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  kubectl delete namespace "$TENANT_NAMESPACE" --ignore-not-found --wait=true >/dev/null
  kubectl create namespace "$TENANT_NAMESPACE" --dry-run=client -o json |
    jq --arg l "$TIER_LABEL" '.metadata.labels[$l] = "workload"' | kubectl create -f - >/dev/null
}

setup() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
}

teardown_file() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  kubectl delete namespace "$TENANT_NAMESPACE" --ignore-not-found --wait=false >/dev/null
}

# Applies the manifest on stdin in the tenant namespace; returns non-zero when admission refuses it.
tenant_apply() {
  kubectl -n "$TENANT_NAMESPACE" apply -f - >"$BATS_TEST_TMPDIR/apply.out" 2>&1
}

@test "an ExternalSecret in a tenant namespace cannot read the local CA key nor the Harbor admin password" {
  for target in stolen-local-ca:platform/local-ca:tls.key stolen-harbor-admin:platform/harbor-admin:password; do
    IFS=: read -r name key property <<<"$target"
    manifest="$(jq -n --arg name "$name" --arg store "$SECRET_STORE" --arg key "$key" --arg property "$property" '{
      apiVersion: "external-secrets.io/v1", kind: "ExternalSecret", metadata: {name: $name},
      spec: {refreshInterval: "1h", secretStoreRef: {kind: "ClusterSecretStore", name: $store},
        target: {name: $name}, data: [{secretKey: "value", remoteRef: {key: $key, property: $property}}]}}')"
    tenant_apply <<<"$manifest" || continue
  done
  deadline=$((SECONDS + DENIAL_WINDOW_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    for name in stolen-local-ca stolen-harbor-admin; do
      if kubectl -n "$TENANT_NAMESPACE" get secret "$name" -o name >/dev/null 2>&1; then
        kubectl -n "$TENANT_NAMESPACE" delete secret "$name" --wait=false >/dev/null 2>&1
        kubectl -n "$TENANT_NAMESPACE" delete externalsecret --all --wait=false >/dev/null 2>&1
        fail "ClusterSecretStore $SECRET_STORE delivered $name into tenant namespace $TENANT_NAMESPACE"
      fi
    done
    sleep 5
  done
  for name in stolen-local-ca stolen-harbor-admin; do
    ready="$(kubectl -n "$TENANT_NAMESPACE" get externalsecret "$name" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
    [ "$ready" != True ] || fail "ExternalSecret $TENANT_NAMESPACE/$name is Ready"
  done
}

@test "the platform-audit role reads credential metadata but not credential values" {
  jwt="$(kubectl -n "$OPENBAO_NAMESPACE" create token "$AUDIT_ROLE" --duration=10m)"
  [ -n "$jwt" ] || fail "cannot issue a token for ServiceAccount $OPENBAO_NAMESPACE/$AUDIT_ROLE"
  # Only exit codes leave the pod: every bao output goes to /dev/null.
  run bash -c 'printf "%s\n" "$1" | kubectl -n "$2" exec -i "$3" -c openbao -- sh -c "
    read -r jwt
    BAO_TOKEN=\"\$(printf %s \"\$jwt\" | bao write -field=token auth/kubernetes/login role=$4 jwt=-)\" || exit 90
    export BAO_TOKEN
    bao kv metadata get -mount=secret platform/harbor-admin >/dev/null 2>&1; metadata=\$?
    bao kv get -mount=secret platform/harbor-admin >/dev/null 2>&1; value=\$?
    echo \"metadata=\$metadata value=\$value\""' _ "$jwt" "$OPENBAO_NAMESPACE" "$OPENBAO_POD" "$AUDIT_ROLE"
  [ "$status" -eq 0 ] || fail "login with Kubernetes auth role $AUDIT_ROLE failed (exit $status)"
  [[ "$output" =~ metadata=([0-9]+)\ value=([0-9]+) ]] || fail "unexpected probe output: $output"
  metadata="${BASH_REMATCH[1]}"
  value="${BASH_REMATCH[2]}"
  [ "$value" -ne 0 ] || fail "$AUDIT_ROLE reads the value of secret/platform/harbor-admin"
  [ "$metadata" -eq 0 ] || fail "$AUDIT_ROLE cannot read the metadata of secret/platform/harbor-admin"
}

@test "an HTTPRoute of a tenant namespace is not accepted by the shared Gateway" {
  manifest="$(jq -n --arg gw "${GATEWAY#*/}" --arg gwns "${GATEWAY%/*}" --arg host "$HARBOR_HOST" '{
    apiVersion: "gateway.networking.k8s.io/v1", kind: "HTTPRoute", metadata: {name: "tenant-hijack"},
    spec: {parentRefs: [{name: $gw, namespace: $gwns}], hostnames: [$host],
      rules: [{matches: [{path: {type: "PathPrefix", value: "/tenant-isolation-probe"}}],
               backendRefs: [{name: "tenant-backend", port: 8080}]}]}}')"
  tenant_apply <<<"$manifest" || return 0
  deadline=$((SECONDS + DENIAL_WINDOW_SECONDS))
  accepted=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    accepted="$(kubectl -n "$TENANT_NAMESPACE" get httproute tenant-hijack -o json | jq -r --arg gw "${GATEWAY#*/}" '
      [.status.parents[]? | select(.parentRef.name == $gw) | .conditions[]? | select(.type == "Accepted") | .status][0] // ""')"
    [ -z "$accepted" ] || break
    sleep 3
  done
  kubectl -n "$TENANT_NAMESPACE" delete httproute tenant-hijack --wait=false >/dev/null
  [ -n "$accepted" ] || fail "Gateway $GATEWAY reported no Accepted condition for the tenant HTTPRoute within ${DENIAL_WINDOW_SECONDS}s"
  [ "$accepted" = False ] || fail "Gateway $GATEWAY accepted a tenant HTTPRoute on $HARBOR_HOST/tenant-isolation-probe"
}

@test "a tenant namespace cannot get a certificate from the platform ClusterIssuer" {
  manifest="$(jq -n --arg issuer "$CLUSTER_ISSUER" '{
    apiVersion: "cert-manager.io/v1", kind: "Certificate", metadata: {name: "tenant-probe"},
    spec: {secretName: "tenant-probe-tls", dnsNames: ["tenant-probe.127.0.0.1.nip.io"],
      issuerRef: {kind: "ClusterIssuer", name: $issuer}}}')"
  tenant_apply <<<"$manifest" || return 0
  deadline=$((SECONDS + DENIAL_WINDOW_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if kubectl -n "$TENANT_NAMESPACE" get secret tenant-probe-tls -o name >/dev/null 2>&1; then
      kubectl -n "$TENANT_NAMESPACE" delete certificate tenant-probe --wait=false >/dev/null
      fail "ClusterIssuer $CLUSTER_ISSUER issued a certificate into tenant namespace $TENANT_NAMESPACE"
    fi
    sleep 5
  done
  conditions="$(kubectl -n "$TENANT_NAMESPACE" get certificate tenant-probe -o json | jq -c '.status.conditions // []')"
  kubectl -n "$TENANT_NAMESPACE" delete certificate tenant-probe --wait=false >/dev/null
  [ "$conditions" != "[]" ] || fail "cert-manager never processed the tenant Certificate: the denial is not observed"
  jq -e 'any(.[]; .type == "Ready" and .status == "True") | not' <<<"$conditions" >/dev/null ||
    fail "the tenant Certificate is Ready: $conditions"
}

@test "dt-bridge rejects a Harbor webhook without the shared secret" {
  port_file="$BATS_TEST_TMPDIR/port-forward.log"
  kubectl -n "${DT_BRIDGE_SERVICE%/*}" port-forward "service/${DT_BRIDGE_SERVICE#*/}" :8080 >"$port_file" 2>&1 &
  forward=$!
  for _ in $(seq 1 30); do
    port="$(grep -oE '127\.0\.0\.1:[0-9]+' "$port_file" | head -n 1 | cut -d: -f2)"
    [ -z "$port" ] || break
    sleep 1
  done
  [ -n "$port" ] || { kill "$forward"; fail "kubectl port-forward to $DT_BRIDGE_SERVICE did not start: $(cat "$port_file")"; }
  event='{"type": "PING", "event_data": {}}'
  without="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data "$event" \
    "http://127.0.0.1:$port/harbor/events")"
  wrong="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
    -H "Authorization: $WRONG_SHARED_SECRET" --data "$event" "http://127.0.0.1:$port/harbor/events")"
  kill "$forward"
  [ "$without" = 401 ] || fail "dt-bridge answered HTTP $without to a webhook without the shared secret header"
  [ "$wrong" = 401 ] || fail "dt-bridge answered HTTP $wrong to a webhook with a wrong shared secret"
}

@test "a pod in a tenant namespace cannot reach dt-bridge nor the VictoriaLogs insert endpoint" {
  image="$(kubectl -n "${RUNTIME_DEMO%/*}" get deployment "${RUNTIME_DEMO#*/}" -o jsonpath='{.spec.template.spec.containers[0].image}')"
  [ -n "$image" ] || fail "deployment $RUNTIME_DEMO has no image"
  dt_bridge="$(kubectl -n "${DT_BRIDGE_SERVICE%/*}" get service "${DT_BRIDGE_SERVICE#*/}" -o jsonpath='{.spec.clusterIP}'):8080"
  victorialogs="$(kubectl -n "${VICTORIALOGS_SERVICE%/*}" get endpointslices \
    -l "kubernetes.io/service-name=${VICTORIALOGS_SERVICE#*/}" -o json | jq -r '[.items[].endpoints[].addresses[]][0] // ""')"
  [ "$dt_bridge" != ":8080" ] || fail "service $DT_BRIDGE_SERVICE has no cluster IP"
  [ -n "$victorialogs" ] || fail "service $VICTORIALOGS_SERVICE has no endpoint"
  victorialogs="$victorialogs:$VICTORIALOGS_PORT"
  probe='import json, os, socket
result = {}
for name in ("dt-bridge", "victorialogs"):
    host, port = os.environ[name.upper().replace("-", "_")].rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=5).close()
        result[name] = "open"
    except OSError as error:
        result[name] = "blocked: " + type(error).__name__
print(json.dumps(result))'
  pod="$(jq -n --arg image "$image" --arg probe "$probe" --arg dt "$dt_bridge" --arg vl "$victorialogs" '{
    apiVersion: "v1", kind: "Pod", metadata: {name: "network-probe"},
    spec: {restartPolicy: "Never", automountServiceAccountToken: false,
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: "RuntimeDefault"}},
      containers: [{name: "probe", image: $image, command: ["python3", "-c", $probe],
        env: [{name: "DT_BRIDGE", value: $dt}, {name: "VICTORIALOGS", value: $vl}],
        resources: {requests: {cpu: "5m", memory: "16Mi"}, limits: {memory: "64Mi"}},
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}]}}')"
  tenant_apply <<<"$pod" || fail "the probe pod was not admitted: $(cat "$BATS_TEST_TMPDIR/apply.out")"
  kubectl -n "$TENANT_NAMESPACE" wait pod network-probe --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s >/dev/null ||
    fail "the probe pod did not complete: $(kubectl -n "$TENANT_NAMESPACE" get pod network-probe -o jsonpath='{.status.phase}')"
  result="$(kubectl -n "$TENANT_NAMESPACE" logs network-probe)"
  kubectl -n "$TENANT_NAMESPACE" delete pod network-probe --wait=false >/dev/null
  jq -e '."dt-bridge" | startswith("blocked")' <<<"$result" >/dev/null ||
    fail "a tenant pod reaches dt-bridge at $dt_bridge: $result"
  jq -e '.victorialogs | startswith("blocked")' <<<"$result" >/dev/null ||
    fail "a tenant pod reaches the VictoriaLogs insert endpoint at $victorialogs: $result"
}
