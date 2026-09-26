#!/usr/bin/env bats
# Golden images replicated from GHCR into Harbor `golden`, live against the kind platform: they
# still verify on their Harbor reference. The Harbor admin password is sent on stdin only.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
load golden

PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
HARBOR_HOST=harbor.127.0.0.1.nip.io
HARBOR_NAMESPACE=harbor
HARBOR_ADMIN_SECRET=harbor-admin
GOLDEN_PROJECT=golden
GOLDEN_REPLICATION=golden-from-ghcr
REPLICATION_TIMEOUT_SECONDS=900

setup_file() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  kubectl -n gateway get secret wildcard-nip-io-tls -o jsonpath='{.data.ca\.crt}' | base64 -d \
    >"$BATS_FILE_TMPDIR/harbor-ca.crt"
  [ -s "$BATS_FILE_TMPDIR/harbor-ca.crt" ] || fail "Secret gateway/wildcard-nip-io-tls has no ca.crt"
}

setup() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  HARBOR_CA="$BATS_FILE_TMPDIR/harbor-ca.crt"
}

# Harbor admin API call; sets HTTP_CODE, HTTP_BODY and HTTP_HEADERS (file paths). The Authorization
# header goes through stdin, never argv or output.
harbor_admin() {
  local method="$1" path="$2" data="${3:-}" password
  password="$(kubectl -n "$HARBOR_NAMESPACE" get secret "$HARBOR_ADMIN_SECRET" -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 -d)"
  [ -n "$password" ] || fail "Secret $HARBOR_NAMESPACE/$HARBOR_ADMIN_SECRET has no HARBOR_ADMIN_PASSWORD"
  HTTP_BODY="$BATS_TEST_TMPDIR/harbor-body.json"
  HTTP_HEADERS="$BATS_TEST_TMPDIR/harbor-headers.txt"
  local extra=()
  [ -z "$data" ] || extra=(-H 'Content-Type: application/json' --data "$data")
  HTTP_CODE="$(printf 'Authorization: Basic %s\n' "$(printf 'admin:%s' "$password" | base64 -w0)" |
    curl -sS --cacert "$HARBOR_CA" -H @- -X "$method" "${extra[@]}" -D "$HTTP_HEADERS" -o "$HTTP_BODY" \
      -w '%{http_code}' "https://$HARBOR_HOST/api/v2.0$path")"
}

# Runs the golden pull-replication policy now and waits for its execution to end; sets
# REPLICATION_STATUS (status and Harbor's status text).
replicate_golden() {
  local policy_id execution_id deadline
  harbor_admin GET "/replication/policies?name=$GOLDEN_REPLICATION"
  [ "$HTTP_CODE" = 200 ] || fail "cannot list replication policies (HTTP $HTTP_CODE)"
  policy_id="$(jq -r --arg n "$GOLDEN_REPLICATION" '.[] | select(.name == $n) | .id' "$HTTP_BODY")"
  [ -n "$policy_id" ] || fail "replication policy $GOLDEN_REPLICATION not found"

  harbor_admin POST /replication/executions "{\"policy_id\": $policy_id}"
  [ "$HTTP_CODE" = 201 ] || fail "cannot start replication $GOLDEN_REPLICATION (HTTP $HTTP_CODE): $(cat "$HTTP_BODY")"
  execution_id="$(tr -d '\r' <"$HTTP_HEADERS" | awk 'tolower($1) == "location:" { print $2 }' | sed 's#.*/##')"
  [[ "$execution_id" =~ ^[0-9]+$ ]] || fail "no execution id in the Location header of the replication start"

  deadline=$((SECONDS + REPLICATION_TIMEOUT_SECONDS))
  while :; do
    harbor_admin GET "/replication/executions/$execution_id"
    [ "$HTTP_CODE" = 200 ] || fail "cannot read replication execution $execution_id (HTTP $HTTP_CODE)"
    REPLICATION_STATUS="$(jq -r '.status + " " + (.status_text // "")' "$HTTP_BODY")"
    case "$REPLICATION_STATUS" in
      Succeeded* | Failed* | Stopped*) return 0 ;;
    esac
    [ "$SECONDS" -lt "$deadline" ] ||
      fail "replication execution $execution_id still $REPLICATION_STATUS after ${REPLICATION_TIMEOUT_SECONDS}s"
    sleep 10
  done
}

@test "replicated golden images verify on their Harbor reference" {
  resolve_golden_run
  replicate_golden

  for name in "${GOLDEN_IMAGES[@]}"; do
    digest="$(golden_ghcr_digest "$name")"
    code="$(curl -sS --cacert "$HARBOR_CA" -o /dev/null -w '%{http_code}' \
      "https://$HARBOR_HOST/api/v2.0/projects/$GOLDEN_PROJECT/repositories/$name/artifacts/$digest")"
    [ "$code" = 200 ] ||
      fail "$GOLDEN_PROJECT/$name@$digest not in Harbor after replication $GOLDEN_REPLICATION ($REPLICATION_STATUS, HTTP $code)"

    harbor_ref="$HARBOR_HOST/$GOLDEN_PROJECT/$name@$digest"
    verify_golden_signed_and_attested "$harbor_ref" --registry-cacert "$HARBOR_CA"
    refute_foreign_identities "$harbor_ref" --registry-cacert "$HARBOR_CA"
  done
}
