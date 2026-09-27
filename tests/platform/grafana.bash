# Grafana helpers for the live observability tests. The admin credentials are read from their cluster Secret
# into local variables and reach curl through stdin, never argv or output. Load after a file defining `fail`.

PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
GRAFANA_HOST=grafana.127.0.0.1.nip.io
OBSERVABILITY_NAMESPACE=observability
GRAFANA_ADMIN_SECRET=grafana-admin
GRAFANA_USER_KEY=admin-user
GRAFANA_PASSWORD_KEY=admin-password
VM_DATASOURCE_UID=victoriametrics
VL_DATASOURCE_UID=victorialogs
VL_DATASOURCE_TYPE=victoriametrics-logs-datasource
WORKLOAD_LABEL=harborlab.io/tier=workload

grafana_setup_file() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  kubectl -n gateway get secret wildcard-nip-io-tls -o jsonpath='{.data.ca\.crt}' | base64 -d \
    >"$BATS_FILE_TMPDIR/platform-ca.crt"
  [ -s "$BATS_FILE_TMPDIR/platform-ca.crt" ] || fail "Secret gateway/wildcard-nip-io-tls has no ca.crt"
}

grafana_setup() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  PLATFORM_CA="$BATS_FILE_TMPDIR/platform-ca.crt"
}

# Grafana HTTP API call as the admin; $3, when given, is a file holding the JSON body.
# Sets HTTP_CODE and HTTP_BODY (file path).
grafana_api() {
  local method="$1" path="$2" data="${3:-}" secret user password
  secret="$(kubectl -n "$OBSERVABILITY_NAMESPACE" get secret "$GRAFANA_ADMIN_SECRET" -o json 2>/dev/null)" || {
    fail "Secret $OBSERVABILITY_NAMESPACE/$GRAFANA_ADMIN_SECRET (Grafana admin) not found"
    return 1
  }
  user="$(jq -r --arg k "$GRAFANA_USER_KEY" '.data[$k] // "" | @base64d' <<<"$secret")"
  password="$(jq -r --arg k "$GRAFANA_PASSWORD_KEY" '.data[$k] // "" | @base64d' <<<"$secret")"
  [ -n "$user" ] && [ -n "$password" ] || {
    fail "Secret $OBSERVABILITY_NAMESPACE/$GRAFANA_ADMIN_SECRET lacks $GRAFANA_USER_KEY or $GRAFANA_PASSWORD_KEY"
    return 1
  }
  HTTP_BODY="$BATS_TEST_TMPDIR/grafana-body.json"
  local extra=()
  [ -z "$data" ] || extra=(-H 'Content-Type: application/json' --data-binary "@$data")
  HTTP_CODE="$(printf 'Authorization: Basic %s\n' "$(printf '%s:%s' "$user" "$password" | base64 -w0)" |
    curl -sS --cacert "$PLATFORM_CA" -H @- -X "$method" "${extra[@]}" -o "$HTTP_BODY" -w '%{http_code}' \
      "https://$GRAFANA_HOST$path" 2>"$BATS_TEST_TMPDIR/grafana-curl.err")" || HTTP_CODE=000
}

# Type of the Grafana datasource of uid $1 on stdout; fails when Grafana does not serve it.
grafana_datasource_type() {
  grafana_api GET "/api/datasources/uid/$1" || return 1
  [ "$HTTP_CODE" = 200 ] || {
    fail "Grafana datasource $1 not readable at https://$GRAFANA_HOST (HTTP $HTTP_CODE): $(head -c 200 "$HTTP_BODY" 2>/dev/null) $(tail -n 1 "$BATS_TEST_TMPDIR/grafana-curl.err" 2>/dev/null)"
    return 1
  }
  jq -r '.type' "$HTTP_BODY"
}

# Runs the query object in file $2 (a panel target, without refId or datasource) on the datasource of uid $1
# over [$3, $4] (epoch milliseconds) through Grafana's /api/ds/query. The response is in HTTP_BODY.
grafana_ds_query() {
  local uid="$1" query="$2" from="$3" to="$4" type request="$BATS_TEST_TMPDIR/ds-query.json"
  type="$(grafana_datasource_type "$uid")" || return 1
  jq -n --slurpfile q "$query" --arg uid "$uid" --arg type "$type" --arg from "$from" --arg to "$to" \
    '{queries: [$q[0] + {refId: "A", datasource: {uid: $uid, type: $type}, intervalMs: 60000, maxDataPoints: 200}],
      from: $from, to: $to}' >"$request"
  grafana_api POST /api/ds/query "$request" || return 1
  [ "$HTTP_CODE" = 200 ] || {
    fail "Grafana /api/ds/query on $uid failed (HTTP $HTTP_CODE): $(head -c 400 "$HTTP_BODY")"
    return 1
  }
  jq -e '[.results[]? | .error // empty] | length == 0' "$HTTP_BODY" >/dev/null || {
    fail "Grafana /api/ds/query on $uid returned an error: $(jq -c '[.results[]?.error]' "$HTTP_BODY" | head -c 400)"
    return 1
  }
}

# jq definitions over a /api/ds/query response. rows: every data frame row as an array of
# {name, type, labels, value}; numbers: every numeric cell; magnitude: the sum of the last numeric value of
# each numeric field (one per series), or the number of rows when the frames hold no number (log lines).
GRAFANA_JQ='def rows: [.results[]?.frames[]? | (.schema.fields // []) as $f | (.data.values // []) as $v
    | range(0; ($v[0] // []) | length) as $i
    | [range(0; $f | length) as $j
        | {name: $f[$j].name, type: ($f[$j].type // ""), labels: ($f[$j].labels // {}), value: $v[$j][$i]}]];
  def numbers: [rows[][] | select(.type == "number" and (.value | type) == "number") | .value];
  def magnitude: [.results[]?.frames[]? | (.schema.fields // []) as $f | (.data.values // []) as $v
      | range(0; $f | length) as $j | select($f[$j].type == "number")
      | [$v[$j][]? | select(type == "number")] | last // empty] as $last
    | if ($last | length) > 0 then ($last | add) else (rows | length) end;'

# Magnitude (see GRAFANA_JQ) of the response in HTTP_BODY on stdout.
grafana_magnitude() {
  jq -r "$GRAFANA_JQ"' magnitude' "$HTTP_BODY"
}
