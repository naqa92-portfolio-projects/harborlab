#!/usr/bin/env bash
# VEX demo: replays the Harbor push event of the first catalog golden image to dt-bridge, which uploads
# the image's attested SBOM, then converts the DHI OpenVEX of its base into a CycloneDX VEX for
# Dependency-Track. Exits 0 once Dependency-Track reports that VEX upload COMPLETED.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="$REPO_ROOT/images/catalog.yaml"
GOLDEN_PROJECT=golden
DT_HOST=dependency-track.127.0.0.1.nip.io
DT_API_KEY_SECRET=dt-bridge/dependency-track-api-key
DT_BRIDGE=dt-bridge/dt-bridge
DT_BRIDGE_EVENTS_PROXY=/api/v1/namespaces/dt-bridge/services/dt-bridge:http/proxy/harbor/events
# dt-bridge waits for Dependency-Track's SBOM analysis before it uploads the VEX.
UPLOAD_TIMEOUT_SECONDS=600
PROCESSING_TIMEOUT_SECONDS=240
POLL_SECONDS=5

# shellcheck source=scripts/demo-lib.sh
source "$REPO_ROOT/scripts/demo-lib.sh"
demo_init

# Dependency-Track `GET /api<path>` with the dt-bridge API key sent through stdin. Sets HTTP_CODE.
dt_api() {
  local api_key
  api_key="$(kubectl -n "${DT_API_KEY_SECRET%/*}" get secret "${DT_API_KEY_SECRET#*/}" \
    -o jsonpath='{.data.api-key}' | base64 -d)"
  [ -n "$api_key" ] || die "Secret $DT_API_KEY_SECRET has no api-key"
  HTTP_CODE="$(printf 'X-Api-Key: %s\n' "$api_key" |
    curl -sS --cacert "$WORK/ca.crt" -H @- -H 'Accept: application/json' -o "$WORK/dt.json" -w '%{http_code}' \
      "https://$DT_HOST/api$1")" || HTTP_CODE=000
}

name="$(yq -r '.images[0].name' "$CATALOG")"
digest="$(yq -r '.images[0].digest' "$CATALOG")"
repository="$GOLDEN_PROJECT/$name"
harbor_api GET "/projects/$GOLDEN_PROJECT/repositories/$name/artifacts/$digest?with_tag=true"
[ "$HTTP_CODE" = 200 ] || die "Harbor has no $repository@$digest (HTTP $HTTP_CODE): run the golden-from-ghcr replication"
tag="$(jq -r '[.tags[]?.name | select(startswith("sha256-") | not)][0] // ""' "$WORK/body.json")"
[ -n "$tag" ] || die "Harbor holds no image tag for $repository@$digest"

echo "demo:vex image: $repository:$tag ($digest)"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n --arg project "$GOLDEN_PROJECT" --arg name "$name" --arg tag "$tag" --arg digest "$digest" '{
    type: "PUSH_ARTIFACT",
    event_data: {
      repository: {namespace: $project, name: $name, repo_full_name: "\($project)/\($name)"},
      resources: [{digest: $digest, tag: $tag}]
    }}' >"$WORK/event.json"
kubectl create --raw "$DT_BRIDGE_EVENTS_PROXY" -f "$WORK/event.json" >/dev/null ||
  die "dt-bridge did not accept the replayed Harbor event"

# dt-bridge logs one JSON entry per step of this image; the upload entry names the DT token.
deadline=$((SECONDS + UPLOAD_TIMEOUT_SECONDS))
token=""
while [ -z "$token" ]; do
  kubectl -n "${DT_BRIDGE%/*}" logs "deployment/${DT_BRIDGE#*/}" --since-time="$since" >"$WORK/dt-bridge.log"
  jq -R -c --arg image "$repository" --arg tag "$tag" \
    'fromjson? | select(type == "object" and .image == $image and .tag == $tag) | {message, token, error}' \
    "$WORK/dt-bridge.log" >"$WORK/entries.json"
  token="$(jq -r 'select(.message == "DHI VEX uploaded") | .token // empty' "$WORK/entries.json" | tail -n 1)"
  [ -n "$token" ] && break
  if jq -e 'select(.message == "VEX not applied" or .message == "image not forwarded"
      or .message == "no DHI VEX statement covers an SBOM component")' "$WORK/entries.json" >/dev/null; then
    die "dt-bridge did not upload a VEX for $repository:$tag: $(jq -r -s 'last | "\(.message) \(.error // "")"' "$WORK/entries.json")"
  fi
  [ "$SECONDS" -lt "$deadline" ] || die "dt-bridge logged no VEX upload for $repository:$tag within ${UPLOAD_TIMEOUT_SECONDS}s"
  sleep "$POLL_SECONDS"
done
echo "dt-bridge uploaded the DHI VEX of $repository:$tag, Dependency-Track token $token"

deadline=$((SECONDS + PROCESSING_TIMEOUT_SECONDS))
while :; do
  dt_api "/v1/event/token/$token"
  status="$(jq -r '.status // ""' "$WORK/dt.json" 2>/dev/null || true)"
  [ "$HTTP_CODE" = 200 ] || die "Dependency-Track token $token not readable (HTTP $HTTP_CODE)"
  case "$status" in
    COMPLETED) break ;;
    FAILED) die "Dependency-Track failed to process the VEX of $repository:$tag (token $token)" ;;
  esac
  [ "$SECONDS" -lt "$deadline" ] || die "Dependency-Track token $token still '$status' after ${PROCESSING_TIMEOUT_SECONDS}s"
  sleep "$POLL_SECONDS"
done
echo "vex accepted: $repository:$tag token $token"
