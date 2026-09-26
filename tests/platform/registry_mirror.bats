#!/usr/bin/env bats
# Transparent containerd mirrors, live against the kind platform: each upstream is served through
# its Harbor proxy-cache project, and pulls fall back upstream when Harbor is down.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
CLUSTER=harborlab
HARBOR_HOST=harbor.127.0.0.1.nip.io
HARBOR_NAMESPACE=harbor
HARBOR_ADMIN_SECRET=harbor-admin
TEST_NAMESPACE=registry-mirror-test
# Harbor stores a proxied platform manifest 20-200 s after the pull and never guarantees a tag.
CACHE_WAIT_SECONDS=240

# "<image>|<proxy-cache project>|<repository in the project>|<keep-alive: sleep or entrypoint>"
# Small pinned images whose layers are shared with no other image the platform runs.
declare -gA PROXY_CASES=(
  [docker.io]="docker.io/library/busybox:1.36.1|dockerhub-proxy|library/busybox|sleep"
  [quay.io]="quay.io/libpod/busybox:1.30.1|quay-proxy|libpod/busybox|sleep"
  [ghcr.io]="ghcr.io/containerd/busybox:1.36|ghcr-proxy|containerd/busybox|sleep"
  [registry.k8s.io]="registry.k8s.io/pause:3.9|k8s-proxy|pause|entrypoint"
  [dhi.io]="dhi.io/busybox:1.37.0-debian13|dhi-proxy|busybox|sleep"
)
# dhi.io needs credentials the node does not hold, so only anonymous upstreams can fall back.
FALLBACK_UPSTREAMS=(docker.io quay.io ghcr.io registry.k8s.io)

fail() {
  echo "$*" >&2
  return 1
}

setup_file() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  kubectl -n gateway get secret wildcard-nip-io-tls -o jsonpath='{.data.ca\.crt}' | base64 -d \
    >"$BATS_FILE_TMPDIR/harbor-ca.crt"
  [ -s "$BATS_FILE_TMPDIR/harbor-ca.crt" ] || fail "Secret gateway/wildcard-nip-io-tls has no ca.crt"
  kubectl create namespace "$TEST_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

setup() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  HARBOR_CA="$BATS_FILE_TMPDIR/harbor-ca.crt"
  NODE="$(kind get nodes --name "$CLUSTER" | head -n 1)"
  [ -n "$NODE" ] || fail "no node for kind cluster $CLUSTER"
  PLATFORM="linux/$(kubectl get node "$NODE" -o jsonpath='{.status.nodeInfo.architecture}')"
}

teardown() {
  [ "${KUBECONFIG:-}" = "$PLATFORM_KUBECONFIG" ] || return 0
  kubectl -n "$TEST_NAMESPACE" delete pod --all --ignore-not-found --wait=true >/dev/null 2>&1 || true

  if [ -f "$BATS_TEST_TMPDIR/harbor-replicas.tsv" ]; then
    while IFS=$'\t' read -r workload replicas; do
      kubectl -n "$HARBOR_NAMESPACE" scale "$workload" --replicas="$replicas"
    done <"$BATS_TEST_TMPDIR/harbor-replicas.tsv"
  fi
  # Argo CD self-heal is restored child first, so `root` never reverts `harbor` mid-restore.
  for app in harbor root; do
    if [ -f "$BATS_TEST_TMPDIR/syncpolicy-$app.json" ]; then
      kubectl -n argocd patch applications.argoproj.io "$app" --type=merge \
        -p "{\"spec\":{\"syncPolicy\":$(cat "$BATS_TEST_TMPDIR/syncpolicy-$app.json")}}" >/dev/null
    fi
  done
  if [ -f "$BATS_TEST_TMPDIR/harbor-replicas.tsv" ]; then
    while IFS=$'\t' read -r workload _; do
      kubectl -n "$HARBOR_NAMESPACE" rollout status "$workload" --timeout=300s
    done <"$BATS_TEST_TMPDIR/harbor-replicas.tsv"
  fi
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
  password="$(kubectl -n "$HARBOR_NAMESPACE" get secret "$HARBOR_ADMIN_SECRET" -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 -d)"
  [ -n "$password" ] || fail "Secret $HARBOR_NAMESPACE/$HARBOR_ADMIN_SECRET has no HARBOR_ADMIN_PASSWORD"
  HTTP_BODY="$BATS_TEST_TMPDIR/harbor-admin-body.json"
  HTTP_CODE="$(printf 'Authorization: Basic %s\n' "$(printf 'admin:%s' "$password" | base64 -w0)" |
    curl -sS --cacert "$HARBOR_CA" -H @- -X "$method" -o "$HTTP_BODY" -w '%{http_code}' \
      "https://$HARBOR_HOST/api/v2.0$path")"
}

remove_from_node() {
  local image="$1"
  docker exec "$NODE" crictl rmi "$image" >/dev/null 2>&1 || true
  run docker exec "$NODE" crictl inspecti "$image"
  [ "$status" -ne 0 ] || fail "$image still present on node $NODE"
}

node_layers() {
  local image_id
  for image_id in $(docker exec "$NODE" crictl images -q); do
    docker exec "$NODE" crictl inspecti -o json "$image_id" | jq -r '.info.imageSpec.rootfs.diff_ids[]'
  done | sort -u
}

start_pod() {
  local name="$1" image="$2" keep_alive="$3" command=""
  [ "$keep_alive" = sleep ] && command='      command: ["sleep", "3600"]'
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: $TEST_NAMESPACE
spec:
  terminationGracePeriodSeconds: 0
  containers:
    - name: probe
      image: $image
      imagePullPolicy: IfNotPresent
$command
EOF
}

# Platform manifest digest from the upstream. dhi.io needs credentials, so its digest is read from
# the index served by the dhi-proxy project: Harbor stores only the platform manifests fetched
# through it, and resolving the index fetches none.
source_platform_digest() {
  local upstream="$1" image="$2" project="$3" repository="$4"
  if [ "$upstream" = dhi.io ]; then
    SSL_CERT_FILE="$HARBOR_CA" crane digest --platform "$PLATFORM" "$HARBOR_HOST/$project/$repository:${image##*:}"
  else
    crane digest --platform "$PLATFORM" "$image"
  fi
}

assert_pull_served_through_proxy() {
  local upstream="$1" image project repository keep_alive platform_digest encoded artifact pod layer cached deadline
  IFS='|' read -r image project repository keep_alive <<<"${PROXY_CASES[$upstream]}"
  pod="mirror-${project%-proxy}"

  harbor_get "/projects/$project"
  [ "$HTTP_CODE" = 200 ] || fail "proxy-cache project $project not readable anonymously on Harbor (HTTP $HTTP_CODE)"

  platform_digest="$(source_platform_digest "$upstream" "$image" "$project" "$repository")"
  [[ "$platform_digest" == sha256:* ]] || fail "no $PLATFORM manifest digest for $image"
  encoded="${repository//\//%252F}"
  artifact="/projects/$project/repositories/$encoded/artifacts/$platform_digest"

  harbor_admin DELETE "/projects/$project/repositories/$encoded"
  [ "$HTTP_CODE" = 200 ] || [ "$HTTP_CODE" = 404 ] || fail "cannot clear $project/$repository (HTTP $HTTP_CODE)"
  harbor_get "$artifact"
  [ "$HTTP_CODE" = 404 ] || fail "artifact $platform_digest still cached in $project (HTTP $HTTP_CODE)"

  remove_from_node "$image"
  node_layers >"$BATS_TEST_TMPDIR/node-layers-before.txt"

  start_pod "$pod" "$image" "$keep_alive"
  run kubectl -n "$TEST_NAMESPACE" wait "pod/$pod" --for=condition=Ready --timeout=180s
  [ "$status" -eq 0 ] || fail "pod pulling $image through the mirror is not Ready: $output"

  # containerd does not fetch a layer it already holds, and Harbor then never caches the artifact.
  for layer in $(docker exec "$NODE" crictl inspecti -o json "$image" | jq -r '.info.imageSpec.rootfs.diff_ids[]'); do
    ! grep -qxF "$layer" "$BATS_TEST_TMPDIR/node-layers-before.txt" ||
      fail "$image layer $layer was already on node $NODE before the pull: pick an image sharing no layer"
  done

  cached=""
  deadline=$((SECONDS + CACHE_WAIT_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    harbor_get "$artifact"
    if [ "$HTTP_CODE" = 200 ]; then
      cached=yes
      break
    fi
    sleep 5
  done
  [ "$cached" = yes ] ||
    fail "artifact $platform_digest ($image, $PLATFORM) never appeared in Harbor project $project within ${CACHE_WAIT_SECONDS} s"
  [ "$(jq -r .digest "$HTTP_BODY")" = "$platform_digest" ] || fail "$project returned another digest for $platform_digest"
}

@test "docker.io pull is served through its Harbor proxy cache" {
  assert_pull_served_through_proxy docker.io
}

@test "quay.io pull is served through its Harbor proxy cache" {
  assert_pull_served_through_proxy quay.io
}

@test "ghcr.io pull is served through its Harbor proxy cache" {
  assert_pull_served_through_proxy ghcr.io
}

@test "registry.k8s.io pull is served through its Harbor proxy cache" {
  assert_pull_served_through_proxy registry.k8s.io
}

@test "dhi.io pull is served through its Harbor proxy cache" {
  assert_pull_served_through_proxy dhi.io
}

@test "pulls fall back upstream when Harbor is scaled to 0" {
  run kubectl -n argocd get applications.argoproj.io harbor
  [ "$status" -eq 0 ] || fail "ArgoCD Application harbor not found: $output"

  # Argo CD self-heal would scale Harbor back up: automated sync is paused, parent first.
  for app in root harbor; do
    kubectl -n argocd get applications.argoproj.io "$app" -o json | jq -c '.spec.syncPolicy' \
      >"$BATS_TEST_TMPDIR/syncpolicy-$app.json"
    kubectl -n argocd patch applications.argoproj.io "$app" --type=json \
      -p '[{"op": "remove", "path": "/spec/syncPolicy/automated"}]' >/dev/null
  done

  kubectl -n "$HARBOR_NAMESPACE" get deploy,statefulset -l app=harbor -o json |
    jq -r '.items[] | "\(.kind | ascii_downcase)/\(.metadata.name)\t\(.spec.replicas)"' \
      >"$BATS_TEST_TMPDIR/harbor-replicas.tsv"
  [ -s "$BATS_TEST_TMPDIR/harbor-replicas.tsv" ] || fail "no Harbor workload labelled app=harbor in namespace $HARBOR_NAMESPACE"
  cut -f1 "$BATS_TEST_TMPDIR/harbor-replicas.tsv" | xargs kubectl -n "$HARBOR_NAMESPACE" scale --replicas=0 >/dev/null
  kubectl -n "$HARBOR_NAMESPACE" wait pod -l app=harbor --for=delete --timeout=300s

  run curl -sS --max-time 10 --cacert "$HARBOR_CA" "https://$HARBOR_HOST/api/v2.0/ping"
  [ "$output" != Pong ] || fail "Harbor still answers after scaling to 0"

  for upstream in "${FALLBACK_UPSTREAMS[@]}"; do
    IFS='|' read -r image project _ keep_alive <<<"${PROXY_CASES[$upstream]}"
    kubectl -n "$TEST_NAMESPACE" delete pod "fallback-${project%-proxy}" --ignore-not-found --wait=true >/dev/null
    remove_from_node "$image"
    start_pod "fallback-${project%-proxy}" "$image" "$keep_alive"
  done

  for upstream in "${FALLBACK_UPSTREAMS[@]}"; do
    IFS='|' read -r image project _ _ <<<"${PROXY_CASES[$upstream]}"
    run kubectl -n "$TEST_NAMESPACE" wait "pod/fallback-${project%-proxy}" --for=condition=Ready --timeout=300s
    [ "$status" -eq 0 ] || fail "$image did not fall back upstream with Harbor at 0: $output"
  done
}
