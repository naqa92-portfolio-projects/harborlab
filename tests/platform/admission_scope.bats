#!/usr/bin/env bats
# Admission scope, live against the cluster started by `task up`: ephemeral containers, namespaces without
# a tier, the tier label itself, and the build identity the running policies trust. Every submission that
# could be admitted is a server-side dry run; the test namespaces are deleted afterwards.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
REPOSITORY=naqa92-portfolio-projects/harborlab
TIER_LABEL=harborlab.io/tier
BOOTSTRAP_NAMESPACES='["kube-system", "cilium", "argocd", "kyverno"]'
RUNTIME_DEMO=runtime-demo/runtime-demo
DOCKER_HUB_IMAGE=docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
UNTIERED_NAMESPACE=admission-scope-test-untiered
TIERED_NAMESPACE=admission-scope-test-workload
EDITOR=tenant-admin
EDITOR_ROLE=admission-scope-test-namespace-editor
SAN_PREFIX="https://github.com/$REPOSITORY/.github/workflows/build-image.yml@refs/heads"
UNDEPLOYED_BRANCH=prd-999-not-deployed

fail() {
  echo "$*" >&2
  return 1
}

setup() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
}

teardown_file() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  kubectl delete clusterrolebinding "$EDITOR_ROLE" --ignore-not-found >/dev/null
  kubectl delete clusterrole "$EDITOR_ROLE" --ignore-not-found >/dev/null
  kubectl delete namespace "$UNTIERED_NAMESPACE" "$TIERED_NAMESPACE" --ignore-not-found --wait=false >/dev/null
}

# The governed image the runtime-demo Deployment runs (a Harbor apps digest that passes every workload rule).
governed_image() {
  kubectl -n "${RUNTIME_DEMO%/*}" get deployment "${RUNTIME_DEMO#*/}" -o jsonpath='{.spec.template.spec.containers[0].image}'
}

# A Pod Security restricted pod on image $2 in namespace $1, as JSON.
restricted_pod() {
  jq -n --arg ns "$1" --arg image "$2" '{
    apiVersion: "v1", kind: "Pod",
    metadata: {name: "admission-scope-probe", namespace: $ns},
    spec: {
      automountServiceAccountToken: false,
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: "RuntimeDefault"}},
      containers: [{name: "probe", image: $image, command: ["python3", "-c", "pass"],
        resources: {limits: {memory: "64Mi"}},
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}]
    }}'
}

# Whether the build-image identity regexp $1 accepts the SAN of branch $2 (whole-string match when $3 is
# "full", as dt-bridge's re.fullmatch; Kyverno's regexp as written otherwise).
accepts_branch() {
  local regexp="$1" branch="$2"
  [ "${3:-}" = full ] && regexp="^(?:$regexp)\$"
  jq -en --arg r "$regexp" --arg s "$SAN_PREFIX/$branch" '$s | test($r)' >/dev/null
}

deployed_revision() {
  kubectl -n argocd get applications.argoproj.io root -o jsonpath='{.spec.source.targetRevision}'
}

@test "kubectl debug cannot add a Docker Hub ephemeral container in a workload namespace" {
  pod="$(kubectl -n "${RUNTIME_DEMO%/*}" get pods -l "app.kubernetes.io/name=${RUNTIME_DEMO#*/}" \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')"
  [ -n "$pod" ] || fail "no running pod of deployment $RUNTIME_DEMO"
  # What kubectl debug --profile=restricted sends: Pod Security passes, only the workload rules can refuse.
  patch="$(jq -nc --arg image "$DOCKER_HUB_IMAGE" '{spec: {ephemeralContainers: [{
    name: "admission-scope-debugger", image: $image, command: ["sleep", "3600"],
    securityContext: {allowPrivilegeEscalation: false, runAsNonRoot: true, capabilities: {drop: ["ALL"]},
      seccompProfile: {type: "RuntimeDefault"}}}]}}')"
  run kubectl -n "${RUNTIME_DEMO%/*}" patch pod "$pod" --subresource=ephemeralcontainers --type=strategic \
    --dry-run=server -o jsonpath='{.spec.ephemeralContainers[*].name}' -p "$patch"
  [ "$status" -ne 0 ] ||
    fail "the API server admits ephemeral container $DOCKER_HUB_IMAGE into ${RUNTIME_DEMO%/*}/$pod (dry run): $output"
  grep -q 'workload-registry' <<<"$output" || fail "the ephemeral container is refused, but not by workload-registry: $output"
}

@test "every namespace running pods outside bootstrap carries a tier label" {
  run kubectl get pods -A -o json
  [ "$status" -eq 0 ] || fail "cannot list pods: $output"
  namespaces="$(jq -r --argjson boot "$BOOTSTRAP_NAMESPACES" '[.items[].metadata.namespace] | unique[]
    | select(. as $n | $boot | index($n) | not)' <<<"$output")"
  run kubectl get namespaces -o json
  [ "$status" -eq 0 ] || fail "cannot list namespaces: $output"
  untiered="$(jq -r --arg l "$TIER_LABEL" --arg names "$namespaces" '($names | split("\n")) as $n
    | .items[] | select(.metadata.name as $m | $n | index($m))
    | select((.metadata.labels[$l] // "") as $t | ["workload", "platform"] | index($t) | not)
    | "\(.metadata.name)=\(.metadata.labels[$l] // "none")"' <<<"$output")"
  [ -z "$untiered" ] ||
    fail "namespaces running pods without $TIER_LABEL=workload|platform: $(tr '\n' ' ' <<<"$untiered")"
}

@test "a pod in a namespace without a tier label is denied" {
  image="$(governed_image)"
  [ -n "$image" ] || fail "deployment $RUNTIME_DEMO has no image"
  kubectl delete namespace "$UNTIERED_NAMESPACE" --ignore-not-found --wait=true >/dev/null
  run kubectl create namespace "$UNTIERED_NAMESPACE"
  if [ "$status" -ne 0 ]; then
    # Required label: a namespace cannot even be created without its tier.
    grep -q "$TIER_LABEL" <<<"$output" || fail "namespace creation failed for another reason: $output"
    return 0
  fi
  run kubectl create --dry-run=server -f - <<<"$(restricted_pod "$UNTIERED_NAMESPACE" "$image")"
  [ "$status" -ne 0 ] || fail "a pod on $image is admitted in $UNTIERED_NAMESPACE, which has no $TIER_LABEL label"
  grep -q "$TIER_LABEL" <<<"$output" || fail "the pod is denied without naming the missing $TIER_LABEL label: $output"
}

@test "a namespace editor cannot remove or change the tier label" {
  kubectl delete namespace "$TIERED_NAMESPACE" --ignore-not-found --wait=true >/dev/null
  kubectl create namespace "$TIERED_NAMESPACE" --dry-run=client -o json |
    jq --arg l "$TIER_LABEL" '.metadata.labels[$l] = "workload"' | kubectl create -f - >/dev/null
  kubectl -n "$TIERED_NAMESPACE" create serviceaccount "$EDITOR" >/dev/null
  kubectl delete clusterrolebinding "$EDITOR_ROLE" --ignore-not-found >/dev/null
  kubectl delete clusterrole "$EDITOR_ROLE" --ignore-not-found >/dev/null
  kubectl create clusterrole "$EDITOR_ROLE" --verb=get,list,watch,patch,update --resource=namespaces >/dev/null
  kubectl create clusterrolebinding "$EDITOR_ROLE" --clusterrole="$EDITOR_ROLE" \
    --serviceaccount="$TIERED_NAMESPACE:$EDITOR" >/dev/null
  as="--as=system:serviceaccount:$TIERED_NAMESPACE:$EDITOR"

  # Control: RBAC lets the editor patch the namespace.
  run kubectl label namespace "$TIERED_NAMESPACE" harborlab.io/probe=ok --overwrite --dry-run=server "$as"
  [ "$status" -eq 0 ] || fail "the editor cannot label its namespace at all (RBAC not effective): $output"

  run kubectl label namespace "$TIERED_NAMESPACE" "$TIER_LABEL-" --dry-run=server "$as"
  [ "$status" -ne 0 ] || fail "a non-admin namespace editor can remove $TIER_LABEL from $TIERED_NAMESPACE (dry run)"
  run kubectl label namespace "$TIERED_NAMESPACE" "$TIER_LABEL=platform" --overwrite --dry-run=server "$as"
  [ "$status" -ne 0 ] || fail "a non-admin namespace editor can move $TIERED_NAMESPACE to the platform tier (dry run)"
}

@test "running admission policies trust main and the deployed platform revision only" {
  revision="$(deployed_revision)"
  [ -n "$revision" ] || fail "Application argocd/root has no targetRevision"
  run kubectl get imagevalidatingpolicies.policies.kyverno.io -o json
  [ "$status" -eq 0 ] || fail "cannot list ImageValidatingPolicies: $output"
  identities="$(jq -r '.items[] | .metadata.name as $p | .. | objects | select(has("subjectRegExp"))
    | select(.subjectRegExp | test("build-image")) | "\($p)|\(.subjectRegExp)"' <<<"$output")"
  [ -n "$identities" ] || fail "no running ImageValidatingPolicy trusts a build-image.yml identity"
  while IFS='|' read -r policy regexp; do
    accepts_branch "$regexp" main || fail "$policy does not trust build-image.yml from main: $regexp"
    if [ "$revision" != main ]; then
      accepts_branch "$regexp" "$revision" ||
        fail "$policy does not trust the deployed platform revision $revision: $regexp"
    fi
    ! accepts_branch "$regexp" "$UNDEPLOYED_BRANCH" ||
      fail "$policy trusts $UNDEPLOYED_BRANCH, a branch this platform is not deployed from: $regexp"
  done <<<"$identities"
}

@test "running dt-bridge trusts main and the deployed platform revision only" {
  revision="$(deployed_revision)"
  [ -n "$revision" ] || fail "Application argocd/root has no targetRevision"
  run kubectl -n dt-bridge get deployment dt-bridge -o json
  [ "$status" -eq 0 ] || fail "cannot read deployment dt-bridge/dt-bridge: $output"
  identities="$(jq -r '.spec.template.spec.containers[].env[]? | select(.name | test("^SIGNER_IDENTITY_"))
    | "\(.name)|\(.value // "")"' <<<"$output")"
  [ -n "$identities" ] || fail "deployment dt-bridge sets no SIGNER_IDENTITY_* variable"
  while IFS='|' read -r name regexp; do
    accepts_branch "$regexp" main full || fail "dt-bridge $name does not trust main: $regexp"
    if [ "$revision" != main ]; then
      accepts_branch "$regexp" "$revision" full || fail "dt-bridge $name does not trust the deployed revision $revision"
    fi
    ! accepts_branch "$regexp" "$UNDEPLOYED_BRANCH" full ||
      fail "dt-bridge $name trusts $UNDEPLOYED_BRANCH, a branch this platform is not deployed from: $regexp"
  done <<<"$identities"
}
