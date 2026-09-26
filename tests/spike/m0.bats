#!/usr/bin/env bats
# M0 spike, live against the kind cluster `harborlab-spike` created by `spike/up.sh`.
# Harbor credentials are read from the cluster at run time and never printed.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
CLUSTER=harborlab-spike
HARBOR_HOST=harbor.127.0.0.1.nip.io
GHCR_SPIKE_IMAGE=ghcr.io/naqa92-portfolio-projects/harborlab/spike/hello:m0
OIDC_ISSUER=https://token.actions.githubusercontent.com
SPIKE_IDENTITY='^https://github\.com/naqa92-portfolio-projects/harborlab/\.github/workflows/spike\.yml@refs/.+$'
FOREIGN_IDENTITY='^https://github\.com/sigstore/cosign/\.github/workflows/.+$'
MIRROR_IMAGE=docker.io/library/busybox:1.36.1

fail() {
  echo "$*" >&2
  return 1
}

setup() {
  if [ ! -f "$BATS_FILE_TMPDIR/spike-up.done" ]; then
    "$REPO_ROOT/spike/up.sh"
    touch "$BATS_FILE_TMPDIR/spike-up.done"
  fi

  export KUBECONFIG="$BATS_FILE_TMPDIR/kubeconfig"
  if [ ! -s "$KUBECONFIG" ]; then
    (umask 077 && kind get kubeconfig --name "$CLUSTER" >"$KUBECONFIG")
  fi

  HARBOR_CA="$BATS_FILE_TMPDIR/harbor-ca.crt"
  if [ ! -s "$HARBOR_CA" ]; then
    kubectl -n harbor get secret harbor-ca -o jsonpath='{.data.ca\.crt}' | base64 -d >"$HARBOR_CA"
    [ -s "$HARBOR_CA" ] || fail "Secret harbor/harbor-ca has no ca.crt"
  fi
  COSIGN_HARBOR=(--registry-cacert "$HARBOR_CA" --certificate-oidc-issuer "$OIDC_ISSUER")
}

# Anonymous Harbor API call; sets HTTP_CODE and HTTP_BODY (a file path).
harbor_get() {
  HTTP_BODY="$BATS_TEST_TMPDIR/harbor-body.json"
  HTTP_CODE="$(curl -sS --cacert "$HARBOR_CA" -o "$HTTP_BODY" -w '%{http_code}' \
    "https://$HARBOR_HOST/api/v2.0$1")"
}

# Harbor admin API call; the Authorization header goes through stdin, never argv or output.
harbor_admin() {
  local method="$1" path="$2" password
  password="$(kubectl -n harbor get secret harbor-core -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 -d)"
  [ -n "$password" ] || fail "Secret harbor/harbor-core has no HARBOR_ADMIN_PASSWORD"
  HTTP_BODY="$BATS_TEST_TMPDIR/harbor-admin-body.json"
  HTTP_CODE="$(printf 'Authorization: Basic %s\n' "$(printf 'admin:%s' "$password" | base64 -w0)" |
    curl -sS --cacert "$HARBOR_CA" -H @- -X "$method" -o "$HTTP_BODY" -w '%{http_code}' \
      "https://$HARBOR_HOST/api/v2.0$path")"
}

kind_node() {
  kind get nodes --name "$CLUSTER" | head -n 1
}

teardown() {
  # Never touch the caller's default cluster when setup did not reach the spike.
  [ "${KUBECONFIG:-}" = "$BATS_FILE_TMPDIR/kubeconfig" ] && [ -s "$KUBECONFIG" ] || return 0

  kubectl -n spike-admission delete pod hello-harbor unsigned-harbor --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl -n spike-mirror delete pod busybox-mirror busybox-fallback --ignore-not-found --wait=true >/dev/null 2>&1 || true

  if [ -f "$BATS_TEST_TMPDIR/harbor-replicas.tsv" ]; then
    while IFS=$'\t' read -r workload replicas; do
      kubectl -n harbor scale "$workload" --replicas="$replicas"
    done <"$BATS_TEST_TMPDIR/harbor-replicas.tsv"
    while IFS=$'\t' read -r workload _; do
      kubectl -n harbor rollout status "$workload" --timeout=300s
    done <"$BATS_TEST_TMPDIR/harbor-replicas.tsv"
  fi
}

@test "replicated image verifies on its Harbor reference" {
  ghcr_digest="$(crane digest "$GHCR_SPIKE_IMAGE")"
  [[ "$ghcr_digest" == sha256:* ]] || fail "no digest for $GHCR_SPIKE_IMAGE on GHCR"

  harbor_get /projects/spike/repositories/hello/artifacts/m0
  [ "$HTTP_CODE" = 200 ] || fail "spike/hello:m0 not replicated into Harbor (HTTP $HTTP_CODE)"
  harbor_digest="$(jq -r .digest "$HTTP_BODY")"
  [ "$harbor_digest" = "$ghcr_digest" ] || fail "Harbor digest $harbor_digest differs from GHCR digest $ghcr_digest"

  harbor_ref="$HARBOR_HOST/spike/hello@$harbor_digest"

  run cosign verify "${COSIGN_HARBOR[@]}" --certificate-identity-regexp "$SPIKE_IDENTITY" "$harbor_ref"
  [ "$status" -eq 0 ] || fail "cosign verify failed on $harbor_ref: $output"

  run cosign verify-attestation "${COSIGN_HARBOR[@]}" --certificate-identity-regexp "$SPIKE_IDENTITY" \
    --type cyclonedx "$harbor_ref"
  [ "$status" -eq 0 ] || fail "CycloneDX attestation not verified on $harbor_ref: $output"

  run cosign verify-attestation "${COSIGN_HARBOR[@]}" --certificate-identity-regexp "$SPIKE_IDENTITY" \
    --type spdxjson "$harbor_ref"
  [ "$status" -eq 0 ] || fail "SPDX attestation not verified on $harbor_ref: $output"

  run cosign verify-attestation "${COSIGN_HARBOR[@]}" --certificate-identity-regexp "$SPIKE_IDENTITY" \
    --type slsaprovenance1 "$harbor_ref"
  [ "$status" -eq 0 ] || fail "SLSA provenance attestation not verified on $harbor_ref: $output"

  run cosign verify "${COSIGN_HARBOR[@]}" --certificate-identity-regexp "$FOREIGN_IDENTITY" "$harbor_ref"
  [ "$status" -ne 0 ] || fail "cosign verify accepted a foreign identity on $harbor_ref"
}

@test "ImageValidatingPolicy admits the replicated image and denies an unsigned one" {
  run kubectl get imagevalidatingpolicies.policies.kyverno.io spike-verify-harbor
  [ "$status" -eq 0 ] || fail "ImageValidatingPolicy spike-verify-harbor not found: $output"

  harbor_get /projects/spike/repositories/unsigned/artifacts/m0
  [ "$HTTP_CODE" = 200 ] || fail "spike/unsigned:m0 missing from Harbor (HTTP $HTTP_CODE)"
  unsigned_ref="$HARBOR_HOST/spike/unsigned@$(jq -r .digest "$HTTP_BODY")"
  run cosign verify "${COSIGN_HARBOR[@]}" --certificate-identity-regexp "$SPIKE_IDENTITY" "$unsigned_ref"
  [ "$status" -ne 0 ] || fail "spike/unsigned:m0 is signed by the spike identity; it cannot prove a denial"

  kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: spike-admission
  labels:
    harborlab.io/tier: workload
EOF

  run kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hello-harbor
  namespace: spike-admission
spec:
  containers:
    - name: hello
      image: $HARBOR_HOST/spike/hello:m0
EOF
  [ "$status" -eq 0 ] || fail "signed Harbor image was not admitted: $output"
  run kubectl -n spike-admission get pod hello-harbor -o jsonpath='{.spec.containers[0].image}'
  [[ "$output" == "$HARBOR_HOST/spike/hello"* ]] || fail "admitted pod image is '$output', not the Harbor reference"

  run kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: unsigned-harbor
  namespace: spike-admission
spec:
  containers:
    - name: unsigned
      image: $HARBOR_HOST/spike/unsigned:m0
EOF
  [ "$status" -ne 0 ] || fail "unsigned Harbor image was admitted"
  [[ "$output" == *spike-verify-harbor* ]] || fail "denial does not come from spike-verify-harbor: $output"
  run kubectl -n spike-admission get pod unsigned-harbor
  [ "$status" -ne 0 ] || fail "pod unsigned-harbor exists after denial"
}

@test "containerd mirror serves through Harbor proxy cache and falls back upstream" {
  node="$(kind_node)"
  [ -n "$node" ] || fail "no node for kind cluster $CLUSTER"

  harbor_admin DELETE /projects/dockerhub-proxy/repositories/library%252Fbusybox
  [ "$HTTP_CODE" = 200 ] || [ "$HTTP_CODE" = 404 ] || fail "cannot clear the proxy cache (HTTP $HTTP_CODE)"
  harbor_get /projects/dockerhub-proxy/repositories/library%252Fbusybox/artifacts/1.36.1
  [ "$HTTP_CODE" = 404 ] || fail "busybox:1.36.1 still cached in dockerhub-proxy (HTTP $HTTP_CODE)"

  docker exec "$node" crictl rmi "$MIRROR_IMAGE" >/dev/null 2>&1 || true
  run docker exec "$node" crictl inspecti "$MIRROR_IMAGE"
  [ "$status" -ne 0 ] || fail "$MIRROR_IMAGE still present on node $node"

  kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: spike-mirror
EOF

  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: busybox-mirror
  namespace: spike-mirror
spec:
  containers:
    - name: busybox
      image: $MIRROR_IMAGE
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
EOF
  run kubectl -n spike-mirror wait pod/busybox-mirror --for=condition=Ready --timeout=180s
  [ "$status" -eq 0 ] || fail "pod pulling $MIRROR_IMAGE through the mirror is not Ready: $output"

  cached=""
  for _ in $(seq 1 30); do
    harbor_get /projects/dockerhub-proxy/repositories/library%252Fbusybox/artifacts/1.36.1
    if [ "$HTTP_CODE" = 200 ]; then
      cached=yes
      break
    fi
    sleep 2
  done
  [ "$cached" = yes ] || fail "busybox:1.36.1 never appeared in Harbor project dockerhub-proxy"

  kubectl -n harbor get deploy,statefulset -o json |
    jq -r '.items[] | "\(.kind | ascii_downcase)/\(.metadata.name)\t\(.spec.replicas)"' \
      >"$BATS_TEST_TMPDIR/harbor-replicas.tsv"
  [ -s "$BATS_TEST_TMPDIR/harbor-replicas.tsv" ] || fail "no Harbor workload found in namespace harbor"
  kubectl -n harbor scale deploy,statefulset --all --replicas=0
  kubectl -n harbor wait pod --all --for=delete --timeout=300s

  run curl -sS --max-time 10 --cacert "$HARBOR_CA" "https://$HARBOR_HOST/api/v2.0/ping"
  [ "$output" != Pong ] || fail "Harbor still answers after scaling to 0"

  kubectl -n spike-mirror delete pod busybox-mirror --wait=true
  docker exec "$node" crictl rmi "$MIRROR_IMAGE" >/dev/null
  run docker exec "$node" crictl inspecti "$MIRROR_IMAGE"
  [ "$status" -ne 0 ] || fail "$MIRROR_IMAGE still present on node $node"

  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: busybox-fallback
  namespace: spike-mirror
spec:
  containers:
    - name: busybox
      image: $MIRROR_IMAGE
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
EOF
  run kubectl -n spike-mirror wait pod/busybox-fallback --for=condition=Ready --timeout=300s
  [ "$status" -eq 0 ] || fail "pull did not fall back upstream with Harbor at 0: $output"
}
