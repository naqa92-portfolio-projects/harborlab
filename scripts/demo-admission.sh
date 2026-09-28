#!/usr/bin/env bash
# Admission demo: submits one pod whose image or spec breaks one workload rule into namespace $2 and
# exits 0 only when the platform reacted as docs/DEMO.md documents.
# Usage: demo-admission.sh <scenario> <namespace>
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO="${1:?usage: $0 <scenario> <namespace>}"
NAMESPACE="${2:?usage: $0 <scenario> <namespace>}"
POD="demo-$SCENARIO"
FIXTURES_REPLICATION=apps-demo-fixtures-from-ghcr
RUNTIME_DEMO=runtime-demo/runtime-demo
# Docker Hub busybox 1.37.0, pinned so every run submits the same image.
DOCKER_HUB_IMAGE=docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
PAUSE_COMMAND='["python3", "-c", "import signal; signal.pause()"]'

# shellcheck source=scripts/demo-lib.sh
source "$REPO_ROOT/scripts/demo-lib.sh"
demo_init
kubectl get namespace "$NAMESPACE" -o name >/dev/null || die "namespace $NAMESPACE does not exist"

# Digest reference of the admission fixture apps/$1:e2e in Harbor, replicated from GHCR when missing.
harbor_fixture() {
  harbor_api GET "/projects/apps/repositories/$1/artifacts/e2e"
  if [ "$HTTP_CODE" = 404 ]; then
    replicate "$FIXTURES_REPLICATION" >&2
    harbor_api GET "/projects/apps/repositories/$1/artifacts/e2e"
  fi
  [ "$HTTP_CODE" = 200 ] || die "Harbor has no apps/$1:e2e (HTTP $HTTP_CODE)"
  echo "$HARBOR_HOST/apps/$1@$(jq -r .digest "$WORK/body.json")"
}

# Scenario table: image, container command (JSON), run as root, expected reaction (deny or warn) and the
# API server's text.
COMMAND="$PAUSE_COMMAND"
ROOT=false
ACTION=deny
case "$SCENARIO" in
  unsigned)
    IMAGE="$(harbor_fixture unsigned)"
    TEXT='Policy workload-image-signature failed: image is not signed by the harborlab build-image workflow'
    ;;
  foreign-signer)
    IMAGE="$(harbor_fixture foreign-signer)"
    TEXT='Policy workload-image-signature failed: image is not signed by the harborlab build-image workflow'
    ;;
  non-golden-base)
    IMAGE="$(harbor_fixture unknown-base)"
    TEXT='Policy workload-golden-base failed: image base is not a golden image of the catalog'
    ;;
  direct-dockerhub)
    IMAGE="$DOCKER_HUB_IMAGE"
    COMMAND='["sleep", "3600"]'
    TEXT='Policy workload-registry failed: image is not served from an allowed workload registry'
    ;;
  root)
    # The governed runtime-demo image: only the pod's security context breaks a rule.
    IMAGE="$(kubectl -n "${RUNTIME_DEMO%/*}" get deployment "${RUNTIME_DEMO#*/}" \
      -o jsonpath='{.spec.template.spec.containers[0].image}')"
    [ -n "$IMAGE" ] || die "deployment $RUNTIME_DEMO has no image"
    COMMAND=null
    ROOT=true
    TEXT='violates PodSecurity "restricted:latest"'
    ;;
  deprecated-base)
    IMAGE="$(harbor_fixture demo-deprecated-base)"
    ACTION=warn
    TEXT='image base is a deprecated golden image'
    ;;
  eol-base)
    # Golden runtimes have no shell: the java image runs its own entrypoint.
    IMAGE="$(harbor_fixture demo-eol-base)"
    COMMAND=null
    TEXT='Policy workload-golden-base failed: image base is an end-of-life golden image'
    ;;
  *) die "unknown admission scenario '$SCENARIO'" ;;
esac

# A restricted-compliant pod (the root scenario only runs as UID 0), so that only the rule under demo reacts.
jq -n --arg ns "$NAMESPACE" --arg pod "$POD" --arg image "$IMAGE" --argjson command "$COMMAND" \
  --argjson root "$ROOT" '{
    apiVersion: "v1", kind: "Pod",
    metadata: {name: $pod, namespace: $ns, labels: {"app.kubernetes.io/name": $pod}},
    spec: {
      automountServiceAccountToken: false,
      securityContext: ((if $root then {runAsUser: 0} else {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532} end)
        + {seccompProfile: {type: "RuntimeDefault"}}),
      containers: [{
        name: "demo", image: $image,
        resources: {requests: {cpu: "5m", memory: "16Mi"}, limits: {memory: "64Mi"}},
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
      } + (if $command == null then {} else {command: $command} end)]
    }}' >"$WORK/pod.json"

echo "demo:$SCENARIO target: $NAMESPACE/$POD image: $IMAGE"
kubectl -n "$NAMESPACE" delete pod "$POD" --ignore-not-found --wait=true >/dev/null

set +e
kubectl create -f "$WORK/pod.json" >"$WORK/answer.txt" 2>&1
created=$?
set -e
cat "$WORK/answer.txt"

exists=false
kubectl -n "$NAMESPACE" get pod "$POD" -o name >/dev/null 2>&1 && exists=true

if [ "$ACTION" = deny ] && [ "$created" -ne 0 ] && [ "$exists" = false ] && grep -qF -- "$TEXT" "$WORK/answer.txt"; then
  echo "demo:$SCENARIO: rejected by the platform as documented"
  exit 0
fi
if [ "$ACTION" = warn ] && [ "$created" -eq 0 ] && [ "$exists" = true ] &&
  grep -E '^Warning: ' "$WORK/answer.txt" | grep -F 'workload-golden-base-deprecated' | grep -qF -- "$TEXT"; then
  echo "demo:$SCENARIO: admitted by the platform with the documented warning"
  exit 0
fi
echo "demo:$SCENARIO: the platform did not react as documented in docs/DEMO.md (pod created: $exists)" >&2
exit 1
