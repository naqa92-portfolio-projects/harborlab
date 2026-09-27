# Helpers of the `task demo:*` scripts (sourced): platform kubeconfig, local CA, Harbor admin API.
# Credentials go from their Kubernetes Secret to curl through stdin, never argv or output.

HARBOR_HOST=harbor.127.0.0.1.nip.io
HARBOR_ADMIN_SECRET=harbor/harbor-admin
REPLICATION_TIMEOUT_SECONDS=600

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# Exports the platform kubeconfig and writes the platform CA into the private work directory $WORK.
demo_init() {
  export KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
  [ -s "$KUBECONFIG" ] || die "platform is not up: $KUBECONFIG missing (run task up)"
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  chmod 700 "$WORK"
  kubectl -n gateway get secret wildcard-nip-io-tls -o jsonpath='{.data.ca\.crt}' | base64 -d >"$WORK/ca.crt"
  [ -s "$WORK/ca.crt" ] || die "Secret gateway/wildcard-nip-io-tls has no ca.crt"
}

# Harbor admin API call. Sets HTTP_CODE; the body is in $WORK/body.json and the headers in $WORK/headers.txt.
harbor_api() {
  local method="$1" path="$2" data="${3:-}" password extra=()
  password="$(kubectl -n "${HARBOR_ADMIN_SECRET%/*}" get secret "${HARBOR_ADMIN_SECRET#*/}" \
    -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 -d)"
  [ -n "$password" ] || die "Secret $HARBOR_ADMIN_SECRET has no HARBOR_ADMIN_PASSWORD"
  [ -z "$data" ] || extra=(-H 'Content-Type: application/json' --data "$data")
  HTTP_CODE="$(printf 'Authorization: Basic %s\n' "$(printf 'admin:%s' "$password" | base64 -w0)" |
    curl -sS --cacert "$WORK/ca.crt" -H @- -X "$method" "${extra[@]}" -D "$WORK/headers.txt" \
      -o "$WORK/body.json" -w '%{http_code}' "https://$HARBOR_HOST/api/v2.0$path")" || HTTP_CODE=000
}

# Runs the Harbor replication $1 and waits for its execution to succeed.
replicate() {
  local policy_id execution_id status deadline
  harbor_api GET "/replication/policies?name=$1"
  [ "$HTTP_CODE" = 200 ] || die "cannot list Harbor replication policies (HTTP $HTTP_CODE)"
  policy_id="$(jq -r --arg n "$1" '.[] | select(.name == $n) | .id' "$WORK/body.json")"
  [ -n "$policy_id" ] || die "Harbor replication policy $1 not found (run task harbor:configure)"
  harbor_api POST /replication/executions "{\"policy_id\": $policy_id}"
  [ "$HTTP_CODE" = 201 ] || die "cannot start Harbor replication $1 (HTTP $HTTP_CODE)"
  execution_id="$(tr -d '\r' <"$WORK/headers.txt" | awk 'tolower($1) == "location:" { print $2 }' | sed 's#.*/##')"
  deadline=$((SECONDS + REPLICATION_TIMEOUT_SECONDS))
  while :; do
    harbor_api GET "/replication/executions/$execution_id"
    status="$(jq -r '.status // ""' "$WORK/body.json" 2>/dev/null || true)"
    case "$status" in
      Succeed | Success) return 0 ;;
      "" | InProgress | Running | Pending | Scheduled) ;;
      *) die "Harbor replication $1 ended '$status'" ;;
    esac
    [ "$SECONDS" -lt "$deadline" ] || die "Harbor replication $1 still '$status' after ${REPLICATION_TIMEOUT_SECONDS}s"
    sleep 5
  done
}
