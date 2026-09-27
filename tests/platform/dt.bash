# Dependency-Track and Harbor admin helpers for the live vulnerability-management tests. Load after
# ../supply-chain/golden.bash and ../supply-chain/apps.bash. Credentials are read from their cluster
# Secret into a local variable and reach curl through stdin, never argv or output.

PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
HARBOR_HOST=harbor.127.0.0.1.nip.io
HARBOR_NAMESPACE=harbor
HARBOR_ADMIN_SECRET=harbor-admin
GOLDEN_PROJECT=golden
GOLDEN_REPLICATION=golden-from-ghcr
APPS_PROJECT=apps
APPS_REPLICATION=apps-from-ghcr
REPLICATION_TIMEOUT_SECONDS=900
DT_HOST=dependency-track.127.0.0.1.nip.io
DT_API_KEY_NAMESPACE=dt-bridge
DT_API_KEY_SECRET=dependency-track-api-key
DT_API_KEY_FIELD=api-key
DT_PAGE_SIZE=500
DT_BRIDGE_NAMESPACE=dt-bridge
DT_BRIDGE_SELECTOR=app.kubernetes.io/name=dt-bridge
DT_BRIDGE_CONTAINER=dt-bridge
# Pod and host share the clock; this absorbs the second truncation of --since-time only.
LOG_MARGIN_SECONDS=2
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

dt_setup_file() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  kubectl -n gateway get secret wildcard-nip-io-tls -o jsonpath='{.data.ca\.crt}' | base64 -d \
    >"$BATS_FILE_TMPDIR/platform-ca.crt"
  [ -s "$BATS_FILE_TMPDIR/platform-ca.crt" ] || fail "Secret gateway/wildcard-nip-io-tls has no ca.crt"
}

dt_setup() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  PLATFORM_CA="$BATS_FILE_TMPDIR/platform-ca.crt"
}

# Harbor admin API call; sets HTTP_CODE, HTTP_BODY and HTTP_HEADERS (file paths).
harbor_admin() {
  local method="$1" path="$2" data="${3:-}" password
  password="$(kubectl -n "$HARBOR_NAMESPACE" get secret "$HARBOR_ADMIN_SECRET" -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 -d)"
  [ -n "$password" ] || fail "Secret $HARBOR_NAMESPACE/$HARBOR_ADMIN_SECRET has no HARBOR_ADMIN_PASSWORD"
  HTTP_BODY="$BATS_TEST_TMPDIR/harbor-body.json"
  HTTP_HEADERS="$BATS_TEST_TMPDIR/harbor-headers.txt"
  local extra=()
  [ -z "$data" ] || extra=(-H 'Content-Type: application/json' --data "$data")
  HTTP_CODE="$(printf 'Authorization: Basic %s\n' "$(printf 'admin:%s' "$password" | base64 -w0)" |
    curl -sS --cacert "$PLATFORM_CA" -H @- -X "$method" "${extra[@]}" -D "$HTTP_HEADERS" -o "$HTTP_BODY" \
      -w '%{http_code}' "https://$HARBOR_HOST/api/v2.0$path")"
}

# Runs the pull-replication policy $1 now and waits for its execution to succeed (`Succeed` in the
# replication API, `Success` in the job service). Sets REPLICATION_STATUS.
replicate() {
  local replication="$1" policy_id execution_id deadline status
  harbor_admin GET "/replication/policies?name=$replication"
  [ "$HTTP_CODE" = 200 ] || fail "cannot list replication policies (HTTP $HTTP_CODE)"
  policy_id="$(jq -r --arg n "$replication" '.[] | select(.name == $n) | .id' "$HTTP_BODY")"
  [ -n "$policy_id" ] || fail "replication policy $replication not found"

  harbor_admin POST /replication/executions "{\"policy_id\": $policy_id}"
  [ "$HTTP_CODE" = 201 ] || fail "cannot start replication $replication (HTTP $HTTP_CODE): $(cat "$HTTP_BODY")"
  execution_id="$(tr -d '\r' <"$HTTP_HEADERS" | awk 'tolower($1) == "location:" { print $2 }' | sed 's#.*/##')"
  [[ "$execution_id" =~ ^[0-9]+$ ]] || fail "no execution id in the Location header of the replication start"

  deadline=$((SECONDS + REPLICATION_TIMEOUT_SECONDS))
  while :; do
    harbor_admin GET "/replication/executions/$execution_id"
    [ "$HTTP_CODE" = 200 ] || fail "cannot read replication execution $execution_id (HTTP $HTTP_CODE)"
    status="$(jq -r '.status // ""' "$HTTP_BODY")"
    REPLICATION_STATUS="$(jq -r '(.status // "") + " " + (.status_text // "")' "$HTTP_BODY")"
    case "$status" in
      "" | InProgress | Running | Pending | Scheduled) ;;
      *) break ;;
    esac
    [ "$SECONDS" -lt "$deadline" ] ||
      fail "replication execution $execution_id still '$REPLICATION_STATUS' after ${REPLICATION_TIMEOUT_SECONDS}s"
    sleep 10
  done
  case "$status" in
    Succeed | Success) ;;
    *) fail "replication execution $execution_id of $replication ended '$REPLICATION_STATUS': $(cat "$HTTP_BODY")" ;;
  esac
}

# Dependency-Track REST call `GET /api<path>` with the dt-bridge API key; extra arguments go to curl
# (e.g. -G --data-urlencode name=…). Sets HTTP_CODE, HTTP_BODY and HTTP_HEADERS (file paths).
dt_get() {
  local path="$1" api_key
  shift
  api_key="$(kubectl -n "$DT_API_KEY_NAMESPACE" get secret "$DT_API_KEY_SECRET" -o jsonpath="{.data.$DT_API_KEY_FIELD}" |
    base64 -d)"
  [ -n "$api_key" ] || {
    fail "Secret $DT_API_KEY_NAMESPACE/$DT_API_KEY_SECRET has no $DT_API_KEY_FIELD"
    return 1
  }
  HTTP_BODY="$BATS_TEST_TMPDIR/dt-body.json"
  HTTP_HEADERS="$BATS_TEST_TMPDIR/dt-headers.txt"
  HTTP_CODE="$(printf 'X-Api-Key: %s\n' "$api_key" |
    curl -sS --cacert "$PLATFORM_CA" -H @- -H 'Accept: application/json' -D "$HTTP_HEADERS" -o "$HTTP_BODY" \
      -w '%{http_code}' "$@" "https://$DT_HOST/api$path")" || HTTP_CODE=000
}

# UUID of the DT project $1 version $2 on stdout; empty when the project does not exist (404).
dt_project_uuid() {
  dt_get /v1/project/lookup -G --data-urlencode "name=$1" --data-urlencode "version=$2" || return 1
  case "$HTTP_CODE" in
    200) jq -r '.uuid' "$HTTP_BODY" ;;
    404) echo "" ;;
    *)
      fail "Dependency-Track project lookup $1 $2 failed (HTTP $HTTP_CODE): $(head -c 300 "$HTTP_BODY")"
      return 1
      ;;
  esac
}

# Last BOM import of the DT project $1 (UUID), in epoch milliseconds (0 when none).
dt_last_bom_import_ms() {
  dt_get "/v1/project/$1" || return 1
  [ "$HTTP_CODE" = 200 ] || {
    fail "cannot read Dependency-Track project $1 (HTTP $HTTP_CODE)"
    return 1
  }
  jq -r '.lastBomImport // 0 | if type == "number" then . else (sub("\\.[0-9]+"; "") | sub("\\+0000$"; "Z")
    | fromdateiso8601 * 1000) end' "$HTTP_BODY"
}

# Every component of the DT project $1 (UUID), one JSON array written to file $2.
dt_components() {
  local uuid="$1" out="$2" page=1 total
  echo '[]' >"$out"
  while :; do
    dt_get "/v1/component/project/$uuid" -G --data-urlencode "pageSize=$DT_PAGE_SIZE" --data-urlencode "pageNumber=$page" ||
      return 1
    [ "$HTTP_CODE" = 200 ] || {
      fail "cannot list components of Dependency-Track project $uuid (HTTP $HTTP_CODE)"
      return 1
    }
    jq -s '.[0] + .[1]' "$out" "$HTTP_BODY" >"$out.next" && mv "$out.next" "$out"
    total="$(tr -d '\r' <"$HTTP_HEADERS" | awk 'tolower($1) == "x-total-count:" { print $2 }')"
    [[ "$total" =~ ^[0-9]+$ ]] || total="$(jq length "$out")"
    [ "$(jq length "$out")" -lt "$total" ] && [ "$(jq length "$HTTP_BODY")" -gt 0 ] || break
    page=$((page + 1))
  done
}

# Findings of the DT project $1 (UUID), suppressed ones included, written to file $2.
dt_findings() {
  dt_get "/v1/finding/project/$1" -G --data-urlencode suppressed=true || return 1
  [ "$HTTP_CODE" = 200 ] || {
    fail "cannot list findings of Dependency-Track project $1 (HTTP $HTTP_CODE)"
    return 1
  }
  cp "$HTTP_BODY" "$2"
}

# Package URLs compared across tools. purl_norm: subpath dropped, common percent-escapes decoded,
# qualifiers sorted. purl_covers($product; $component): an OpenVEX product (Debian ones name the source
# package) covers an SBOM component of the same type and namespace whose name or `upstream` qualifier is
# the product's name, at the product's version when it has one.
PURL_JQ='def purl_decode: gsub("%2[Bb]"; "+") | gsub("%3[Aa]"; ":") | gsub("%40"; "@") | gsub("%7[Ee]"; "~");
  def purl_norm: split("#")[0] | split("?") as $p
    | ($p[0] | purl_decode) + (if ($p[1] // "") == "" then "" else "?" + ($p[1] | split("&") | map(purl_decode) | sort | join("&")) end);
  def purl_parts: split("#")[0] | split("?") as $p | ($p[0] | capture("^(?<path>[^@]*)(@(?<version>.*))?$")) as $b
    | { namespace: ($b.path | sub("/[^/]*$"; "")), name: ($b.path | sub("^.*/"; "") | purl_decode),
        version: ($b.version // null | if . == null or . == "" then null else purl_decode end),
        upstream: ([($p[1] // "") | split("&")[] | select(startswith("upstream=")) | sub("^upstream="; "") | purl_decode
          | split("@")[0]][0] // null) };
  def purl_covers($product; $component): ($product | purl_parts) as $p | ($component | purl_parts) as $c
    | $p.namespace == $c.namespace and ($p.name == $c.name or $p.name == $c.upstream)
      and ($p.version == null or $p.version == $c.version);'

# Unique normalised purls of a CycloneDX document's components, nested ones included, from stdin.
cyclonedx_purls() {
  jq -r "$PURL_JQ"' def comps: .[]? | (., (.components // [] | comps));
    [.components // [] | comps | .purl // empty | purl_norm] | unique[]'
}

# jq definitions over purl_parts (PURL_JQ): parts_cover is purl_covers on pre-parsed purls, so a VEX product
# is compared with ~3000 SBOM components without re-parsing them.
VEX_JQ="$PURL_JQ"'
  def parts_cover($p; $c): $p.namespace == $c.namespace and ($p.name == $c.name or $p.name == $c.upstream)
    and ($p.version == null or $p.version == $c.version);
  def comps: .[]? | (., (.components // [] | comps));'

# Writes to file $2 the components of the CycloneDX SBOM in file $1 (nested ones included) that have a purl:
# [{ref, purl, norm, parts}].
attested_components() {
  jq "$VEX_JQ"' [.components // [] | comps | select((.purl // "") != "")
      | {ref: (.["bom-ref"] // ""), purl, norm: (.purl | purl_norm), parts: (.purl | purl_parts)}]' "$1" >"$2"
}

# dt-bridge log entries (JSON lines) about image $1 tag $2 since $3 (RFC 3339), as a JSON array in file $4.
dt_bridge_entries() {
  local raw="$BATS_TEST_TMPDIR/dt-bridge.log"
  kubectl -n "$DT_BRIDGE_NAMESPACE" logs -l "$DT_BRIDGE_SELECTOR" -c "$DT_BRIDGE_CONTAINER" --tail=-1 \
    --since-time="$3" >"$raw" 2>"$raw.err" || {
    fail "cannot read the dt-bridge logs: $(tail -n 3 "$raw.err")"
    return 1
  }
  jq -R -n --arg image "$1" --arg tag "$2" \
    '[inputs | fromjson? | select(type == "object" and .image == $image and .tag == $tag)]' "$raw" >"$4"
}
