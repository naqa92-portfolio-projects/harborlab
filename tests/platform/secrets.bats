#!/usr/bin/env bats
# Platform credentials, live against the cluster started by `task up`.
# Credential values are measured inside the OpenBao pod or through jq; they are never printed.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
OPENBAO_NAMESPACE=openbao
OPENBAO_POD=openbao-0
AUDIT_ROLE=platform-audit
SECRET_STORE=openbao

# One entry per platform credential:
#   "<KV v2 path under mount secret/>|<field>|<namespace>/<Kubernetes Secret>|<Secret key>"
PLATFORM_CREDENTIALS=()

fail() {
  echo "$*" >&2
  return 1
}

setup() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
}

# Runs a shell script in the OpenBao container, logged in with the read-only audit role through
# Kubernetes auth. The service account JWT goes through stdin, the OpenBao token stays in the pod.
openbao_audit() {
  local script="$1" jwt
  shift
  jwt="$(kubectl -n "$OPENBAO_NAMESPACE" create token "$AUDIT_ROLE" --duration=10m)"
  [ -n "$jwt" ] || fail "cannot issue a token for ServiceAccount $OPENBAO_NAMESPACE/$AUDIT_ROLE"
  printf '%s\n' "$jwt" | kubectl -n "$OPENBAO_NAMESPACE" exec -i "$OPENBAO_POD" -c openbao -- sh -ec '
    read -r jwt
    BAO_TOKEN="$(printf %s "$jwt" | bao write -field=token auth/kubernetes/login role='"$AUDIT_ROLE"' jwt=-)"
    export BAO_TOKEN
    '"$script" sh "$@"
}

@test "OpenBao holds every platform credential" {
  run kubectl -n "$OPENBAO_NAMESPACE" exec "$OPENBAO_POD" -c openbao -- bao status -format=json
  [ "$status" -eq 0 ] || fail "OpenBao is not initialized and unsealed (bao status exit $status): $output"
  [ "$(jq -r '.initialized and (.sealed | not)' <<<"$output")" = true ] ||
    fail "OpenBao is not initialized and unsealed: $output"

  run openbao_audit 'bao secrets list -format=json'
  [ "$status" -eq 0 ] || fail "login with Kubernetes auth role $AUDIT_ROLE or mount listing failed: $output"
  [ "$(jq -r '."secret/" | "\(.type) \(.options.version)"' <<<"$output")" = "kv 2" ] ||
    fail "OpenBao has no KV v2 engine mounted at secret/"

  for credential in "${PLATFORM_CREDENTIALS[@]}"; do
    IFS='|' read -r path field _ _ <<<"$credential"
    run openbao_audit 'bao kv get -mount=secret -field="$2" "$1" | tr -d "\n" | wc -c' "$path" "$field"
    [ "$status" -eq 0 ] || fail "OpenBao secret/$path field $field is not readable by $AUDIT_ROLE"
    [ "$output" -gt 0 ] || fail "OpenBao secret/$path field $field is empty"
  done
}

@test "credential Secrets are delivered only by External Secrets" {
  run kubectl get clustersecretstores.external-secrets.io "$SECRET_STORE" -o json
  [ "$status" -eq 0 ] || fail "ClusterSecretStore $SECRET_STORE not found: $output"
  store="$output"
  [ "$(jq -r '.status.conditions[]? | select(.type == "Ready") | .status' <<<"$store")" = True ] ||
    fail "ClusterSecretStore $SECRET_STORE is not Ready: $(jq -c '.status' <<<"$store")"
  [ "$(jq -r '.spec.provider.vault | "\(.path) \(.version) \(.auth.kubernetes != null)"' <<<"$store")" = "secret v2 true" ] ||
    fail "ClusterSecretStore $SECRET_STORE does not read KV v2 mount secret/ with Kubernetes auth"

  run kubectl get externalsecrets.external-secrets.io -A -o json
  [ "$status" -eq 0 ] || fail "cannot list ExternalSecrets: $output"
  not_ready="$(jq -r '.items[]
    | select(any(.status.conditions[]?; .type == "Ready" and .status == "True") | not)
    | "\(.metadata.namespace)/\(.metadata.name)"' <<<"$output")"
  [ -z "$not_ready" ] || fail "ExternalSecrets not Ready: $not_ready"

  for credential in "${PLATFORM_CREDENTIALS[@]}"; do
    IFS='|' read -r path _ secret_ref key <<<"$credential"
    namespace="${secret_ref%%/*}"
    secret="${secret_ref#*/}"

    run kubectl -n "$namespace" get secret "$secret" -o json
    [ "$status" -eq 0 ] || fail "Secret $secret_ref not found"
    [ "$(jq -r --arg k "$key" '.data[$k] // "" | length' <<<"$output")" -gt 0 ] ||
      fail "Secret $secret_ref key $key is empty"
    owner="$(jq -r '.metadata.ownerReferences[]? | select(.kind == "ExternalSecret" and .controller == true) | .name' <<<"$output")"
    [ -n "$owner" ] || fail "Secret $secret_ref is not owned by an ExternalSecret"

    run kubectl -n "$namespace" get externalsecrets.external-secrets.io "$owner" -o json
    [ "$status" -eq 0 ] || fail "ExternalSecret $namespace/$owner not found"
    [ "$(jq -r '.spec.secretStoreRef | "\(.kind)/\(.name)"' <<<"$output")" = "ClusterSecretStore/$SECRET_STORE" ] ||
      fail "ExternalSecret $namespace/$owner does not use ClusterSecretStore $SECRET_STORE"
    jq -e --arg p "$path" 'any(.spec.data[]?, .spec.dataFrom[]?.extract?; .remoteRef.key? // .key? | . == $p)' \
      <<<"$output" >/dev/null || fail "ExternalSecret $namespace/$owner does not read OpenBao path secret/$path"
  done
}
