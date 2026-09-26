#!/usr/bin/env bash
# Converges the Harbor configuration through its REST API: list, then create or update what differs.
# Prints "<category>: already in place" for each category left unchanged. Credentials travel on stdin
# or in files of a private work directory, never in argv or output.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
OPENBAO_INIT="$REPO_ROOT/.local/openbao/init.json"
HARBOR_URL=https://harbor.127.0.0.1.nip.io
HARBOR_READY_TIMEOUT_SECONDS=600

# "<proxy-cache project>|<endpoint name>|<endpoint type>|<endpoint URL>|<OpenBao credential path or ->"
PROXY_CACHES=(
  "dockerhub-proxy|dockerhub|docker-hub|https://hub.docker.com|-"
  "quay-proxy|quay|quay|https://quay.io|-"
  "ghcr-proxy|ghcr|github-ghcr|https://ghcr.io|-"
  "k8s-proxy|k8s|docker-registry|https://registry.k8s.io|-"
  "dhi-proxy|dhi|docker-registry|https://dhi.io|platform/dhi"
)

# "<governed project>|<pull-replication policy>|<GHCR name filter>"; no tag filter, so the cosign
# referrers fallback tags (sha256-*) are replicated with the images.
GOVERNED_PROJECTS=(
  "golden|golden-from-ghcr|naqa92-portfolio-projects/harborlab/golden/**"
  "apps|apps-from-ghcr|naqa92-portfolio-projects/harborlab/apps/**"
)
REPLICATION_REGISTRY=ghcr
# Harbor cron expressions carry a leading seconds field.
REPLICATION_CRON="0 */15 * * * *"
RETENTION_CRON="0 0 3 * * *"
RETAINED_PER_REPOSITORY=10

WEBHOOK_NAME=dt-bridge
WEBHOOK_ADDRESS=http://dt-bridge.dt-bridge.svc.cluster.local:8080/harbor/events
WEBHOOK_EVENTS='["PUSH_ARTIFACT", "REPLICATION"]'

# Harbor prefixes system robot names with "robot$".
ROBOT_NAME=dt-bridge
ROBOT_KV_PATH=platform/harbor-robot-dt-bridge
ROBOT_ACCESS='[
  {"resource": "repository", "action": "pull"},
  {"resource": "repository", "action": "list"},
  {"resource": "artifact", "action": "read"},
  {"resource": "artifact", "action": "list"},
  {"resource": "tag", "action": "list"},
  {"resource": "accessory", "action": "list"}
]'

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"
umask 077

[ -s "$KUBECONFIG" ] || die "platform is not up: $KUBECONFIG missing (run task up)"
[ -s "$OPENBAO_INIT" ] || die "$OPENBAO_INIT missing (run task up)"

CA="$WORK/ca.crt"
kubectl -n gateway get secret wildcard-nip-io-tls -o jsonpath='{.data.ca\.crt}' | base64 -d >"$CA"
[ -s "$CA" ] || die "Secret gateway/wildcard-nip-io-tls has no ca.crt"

admin_password="$(kubectl -n harbor get secret harbor-admin -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 -d)"
[ -n "$admin_password" ] || die "Secret harbor/harbor-admin has no HARBOR_ADMIN_PASSWORD"
printf 'Authorization: Basic %s\n' "$(printf 'admin:%s' "$admin_password" | base64 -w0)" >"$WORK/admin-auth"
unset admin_password

# Runs a shell script in the OpenBao container with the root token on stdin.
bao_root() {
  local script="$1"
  shift
  { jq -r .root_token "$OPENBAO_INIT"; cat; } |
    kubectl -n openbao exec -i openbao-0 -c openbao -- sh -ec 'read -r BAO_TOKEN; export BAO_TOKEN; '"$script" sh "$@"
}

# Harbor admin API call; the body is a file, the response lands in $WORK/response.
api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS --cacert "$CA" -H @"$WORK/admin-auth" -X "$method" -o "$WORK/response" -w '%{http_code}')
  [ -z "$body" ] || args+=(-H 'Content-Type: application/json' --data-binary @"$body")
  curl "${args[@]}" "$HARBOR_URL/api/v2.0$path"
}

expect() {
  local expected="$1" code
  shift
  code="$(api "$@")"
  [ "$code" = "$expected" ] || die "Harbor API $1 $2 returned HTTP $code: $(head -c 500 "$WORK/response")"
}

# Prints the body of an admin GET.
get() {
  expect 200 GET "$1"
  cat "$WORK/response"
}

# Writes the JSON built by the jq program (and its arguments) to a body file and prints its path.
body() {
  jq -n "$@" >"$WORK/body.json"
  printf '%s' "$WORK/body.json"
}

CATEGORY=""
CHANGES=0
begin() {
  CATEGORY="$1"
  CHANGES=0
}
changed() {
  printf '%s: %s\n' "$CATEGORY" "$*"
  CHANGES=$((CHANGES + 1))
}
finish() {
  if [ "$CHANGES" -eq 0 ]; then
    printf '%s: already in place\n' "$CATEGORY"
  else
    printf '%s: %d change(s) applied\n' "$CATEGORY" "$CHANGES"
  fi
}

wait_for_harbor() {
  local deadline=$((SECONDS + HARBOR_READY_TIMEOUT_SECONDS))
  until [ "$(curl -sS --max-time 5 --cacert "$CA" "$HARBOR_URL/api/v2.0/ping" 2>/dev/null)" = Pong ] &&
    [ "$(api GET /users/current)" = 200 ]; do
    [ "$SECONDS" -lt "$deadline" ] || die "Harbor does not answer on $HARBOR_URL with the admin credential"
    sleep 5
  done
}

registry_id() {
  get "/registries?page_size=100" | jq -r --arg n "$1" '.[] | select(.name == $n) | .id'
}

# Creates or updates a registry endpoint; a credential is read from OpenBao into a private file.
ensure_registry() {
  local name="$1" type="$2" url="$3" credential="$4" current id access_key=""
  if [ "$credential" != - ]; then
    bao_root 'bao kv get -mount=secret -format=json "$1"' "$credential" </dev/null |
      jq '.data.data | {access_key: .username, access_secret: .token}' >"$WORK/credential.json"
    access_key="$(jq -r .access_key "$WORK/credential.json")"
    [ -n "$access_key" ] || die "OpenBao secret/$credential has no username"
  fi
  current="$(get "/registries?page_size=100" | jq -c --arg n "$name" '.[] | select(.name == $n)')"
  if [ -z "$current" ]; then
    if [ "$credential" = - ]; then
      expect 201 POST /registries "$(body --arg n "$name" --arg t "$type" --arg u "$url" \
        '{name: $n, type: $t, url: $u, insecure: false}')"
    else
      expect 201 POST /registries "$(body --arg n "$name" --arg t "$type" --arg u "$url" \
        --slurpfile c "$WORK/credential.json" \
        '{name: $n, type: $t, url: $u, insecure: false,
          credential: {type: "basic", access_key: $c[0].access_key, access_secret: $c[0].access_secret}}')"
    fi
    changed "created registry endpoint $name ($type, $url)"
    return
  fi
  [ "$(jq -r .type <<<"$current")" = "$type" ] || die "registry endpoint $name has type $(jq -r .type <<<"$current"), expected $type"
  if [ "$(jq -r '"\(.url) \(.insecure // false) \(.credential.access_key // "")"' <<<"$current")" != "$url false $access_key" ]; then
    id="$(jq -r .id <<<"$current")"
    if [ "$credential" = - ]; then
      expect 200 PUT "/registries/$id" "$(body --arg u "$url" '{url: $u, insecure: false}')"
    else
      expect 200 PUT "/registries/$id" "$(body --arg u "$url" --slurpfile c "$WORK/credential.json" \
        '{url: $u, insecure: false, credential_type: "basic", access_key: $c[0].access_key, access_secret: $c[0].access_secret}')"
    fi
    changed "updated registry endpoint $name"
  fi
}

# Creates a public project, a proxy cache when a registry id is given.
ensure_project() {
  local name="$1" registry="${2:-}" registry_id=0 code
  [ -z "$registry" ] || registry_id="$(registry_id "$registry")"
  code="$(api GET "/projects/$name")"
  if [ "$code" = 404 ]; then
    expect 201 POST /projects "$(body --arg n "$name" --argjson r "$registry_id" \
      '{project_name: $n, metadata: {public: "true"}, storage_limit: -1}
        + (if $r > 0 then {registry_id: $r} else {} end)')"
    changed "created project $name"
    return
  fi
  [ "$code" = 200 ] || die "Harbor API GET /projects/$name returned HTTP $code"
  [ "$(jq -r '.registry_id // 0' "$WORK/response")" = "$registry_id" ] ||
    die "project $name is bound to registry id $(jq -r '.registry_id // 0' "$WORK/response"), expected $registry_id"
  if [ "$(jq -r .metadata.public "$WORK/response")" != true ]; then
    expect 200 PUT "/projects/$name" "$(body '{metadata: {public: "true"}}')"
    changed "made project $name public"
  fi
}

configure_proxy_caches() {
  local entry project name type url credential
  begin "proxy caches"
  for entry in "${PROXY_CACHES[@]}"; do
    IFS='|' read -r project name type url credential <<<"$entry"
    ensure_registry "$name" "$type" "$url" "$credential"
    ensure_project "$project" "$name"
  done
  rm -f "$WORK/credential.json"
  finish
}

configure_projects() {
  local entry project
  begin "projects"
  for entry in "${GOVERNED_PROJECTS[@]}"; do
    IFS='|' read -r project _ _ <<<"$entry"
    ensure_project "$project"
  done
  finish
}

# Sigstore bundles arrive as OCI referrers (ADR 0001), so cosign content trust is not enforced.
configure_deployment_security() {
  local entry project
  begin "deployment security"
  for entry in "${GOVERNED_PROJECTS[@]}"; do
    IFS='|' read -r project _ _ <<<"$entry"
    if [ "$(get "/projects/$project" | jq -r '.metadata | "\(.prevent_vul) \(.severity) \(.auto_scan)"')" != "true critical true" ]; then
      expect 200 PUT "/projects/$project" "$(body '{metadata: {prevent_vul: "true", severity: "critical", auto_scan: "true"}}')"
      changed "prevent_vul, severity=critical and auto_scan set on $project"
    fi
  done
  finish
}

configure_replication() {
  local entry project policy filter src_id current id
  begin "replication rules"
  src_id="$(registry_id "$REPLICATION_REGISTRY")"
  [ -n "$src_id" ] || die "registry endpoint $REPLICATION_REGISTRY is missing"
  for entry in "${GOVERNED_PROJECTS[@]}"; do
    IFS='|' read -r project policy filter <<<"$entry"
    body --arg n "$policy" --argjson r "$src_id" --arg p "$project" --arg f "$filter" --arg c "$REPLICATION_CRON" '{
      name: $n, description: "Pull \($f) from GHCR into Harbor project \($p)",
      src_registry: {id: $r}, dest_namespace: $p, dest_namespace_replace_count: -1,
      filters: [{type: "name", value: $f}],
      trigger: {type: "scheduled", trigger_settings: {cron: $c}},
      override: true, enabled: true, deletion: false
    }' >/dev/null
    mv "$WORK/body.json" "$WORK/policy.json"
    current="$(get "/replication/policies?page_size=100" | jq -c --arg n "$policy" '.[] | select(.name == $n)')"
    if [ -z "$current" ]; then
      expect 201 POST /replication/policies "$WORK/policy.json"
      changed "created $policy"
      continue
    fi
    if ! jq -e --argjson live "$current" '
        def view: {description, enabled, override, deletion, src: .src_registry.id, dest_namespace,
          dest_namespace_replace_count, trigger: {type: .trigger.type, cron: .trigger.trigger_settings.cron},
          filters: [.filters[]? | {type, value}]};
        view == ($live | view)' "$WORK/policy.json" >/dev/null; then
      id="$(jq -r .id <<<"$current")"
      expect 200 PUT "/replication/policies/$id" "$WORK/policy.json"
      changed "updated $policy"
    fi
  done
  finish
}

# Stores the robot credential held in $WORK/robot.json ({name, secret}) in OpenBao.
store_robot_credential() {
  jq '{username: .name, password: .secret}' "$WORK/robot.json" |
    bao_root 'bao kv put -mount=secret "$1" - >/dev/null' "$ROBOT_KV_PATH"
  rm -f "$WORK/robot.json"
}

# HTTP status of a registry token request with the robot credential stored in OpenBao.
stored_robot_token_status() {
  bao_root 'bao kv get -mount=secret -format=json "$1" 2>/dev/null || true' "$ROBOT_KV_PATH" </dev/null |
    jq -r --arg n "robot\$$ROBOT_NAME" '.data.data // {} | select(.username == $n and (.password // "") != "")
      | "Authorization: Basic " + ("\(.username):\(.password)" | @base64)' >"$WORK/robot-auth"
  if [ ! -s "$WORK/robot-auth" ]; then
    echo none
    return
  fi
  curl -sS --cacert "$CA" -H @"$WORK/robot-auth" -o /dev/null -w '%{http_code}' \
    "$HARBOR_URL/service/token?service=harbor-registry&scope=repository:golden/probe:pull"
  rm -f "$WORK/robot-auth"
}

configure_robots() {
  local current id permissions
  begin "robots"
  permissions="$(jq -c --argjson a "$ROBOT_ACCESS" '[.[] | {kind: "project", namespace: ., access: $a}]' <<<'["apps", "golden"]')"
  body --arg n "$ROBOT_NAME" --argjson p "$permissions" '{
    name: $n, description: "Read-only access of dt-bridge to the governed projects",
    level: "system", duration: -1, disable: false, permissions: $p
  }' >/dev/null
  mv "$WORK/body.json" "$WORK/robot-desired.json"

  current="$(get "/robots?page_size=100" | jq -c --arg n "robot\$$ROBOT_NAME" '.[] | select(.name == $n)')"
  if [ -z "$current" ]; then
    expect 201 POST /robots "$WORK/robot-desired.json"
    mv "$WORK/response" "$WORK/robot.json"
    store_robot_credential
    changed "created robot\$$ROBOT_NAME, credential stored in OpenBao secret/$ROBOT_KV_PATH"
    finish
    return
  fi

  id="$(jq -r .id <<<"$current")"
  if ! jq -e --argjson live "$current" '
      def view: {description, level, duration, disable,
        permissions: ([.permissions[] | {kind, namespace, access: ([.access[] | {resource, action}] | sort)}] | sort_by(.namespace))};
      view == ($live | view)' "$WORK/robot-desired.json" >/dev/null; then
    jq --argjson id "$id" --arg n "robot\$$ROBOT_NAME" '. + {id: $id, name: $n}' "$WORK/robot-desired.json" >"$WORK/body.json"
    expect 200 PUT "/robots/$id" "$WORK/body.json"
    changed "updated robot\$$ROBOT_NAME permissions"
  fi

  if [ "$(stored_robot_token_status)" != 200 ]; then
    # An empty secret makes Harbor generate a new one and return it.
    expect 200 PATCH "/robots/$id" "$(body '{secret: ""}')"
    jq --arg n "robot\$$ROBOT_NAME" '{name: $n, secret: .secret}' "$WORK/response" >"$WORK/robot.json"
    rm -f "$WORK/response"
    store_robot_credential
    changed "refreshed the robot\$$ROBOT_NAME secret, stored in OpenBao secret/$ROBOT_KV_PATH"
  fi
  finish
}

# Tags are immutable except the sha256-* referrers fallback tags, which later attestations update.
configure_immutability() {
  local entry project rule
  begin "immutability"
  for entry in "${GOVERNED_PROJECTS[@]}"; do
    IFS='|' read -r project _ _ <<<"$entry"
    rule="$(get "/projects/$project/immutabletagrules" | jq -c '.[]
      | select(any(.scope_selectors.repository[]; .decoration == "repoMatches" and .pattern == "**")
        and any(.tag_selectors[]; .decoration == "excludes" and .pattern == "sha256-*"))' | head -n 1)"
    body '{
      disabled: false, action: "immutable", template: "immutable_template",
      scope_selectors: {repository: [{kind: "doublestar", decoration: "repoMatches", pattern: "**"}]},
      tag_selectors: [{kind: "doublestar", decoration: "excludes", pattern: "sha256-*"}]
    }' >/dev/null
    if [ -z "$rule" ]; then
      expect 201 POST "/projects/$project/immutabletagrules" "$WORK/body.json"
      changed "created the immutable rule of $project"
    elif [ "$(jq -r .disabled <<<"$rule")" = true ]; then
      jq --argjson id "$(jq .id <<<"$rule")" '. + {id: $id}' "$WORK/body.json" >"$WORK/rule.json"
      expect 200 PUT "/projects/$project/immutabletagrules/$(jq -r .id <<<"$rule")" "$WORK/rule.json"
      changed "enabled the immutable rule of $project"
    fi
  done
  finish
}

# Keeps the most recently pushed artifacts of each repository and every referrers fallback tag.
configure_retention() {
  local entry project project_id retention_id
  begin "retention"
  for entry in "${GOVERNED_PROJECTS[@]}"; do
    IFS='|' read -r project _ _ <<<"$entry"
    get "/projects/$project" >"$WORK/project.json"
    project_id="$(jq -r .project_id "$WORK/project.json")"
    retention_id="$(jq -r '.metadata.retention_id // ""' "$WORK/project.json")"
    body --argjson ref "$project_id" --argjson k "$RETAINED_PER_REPOSITORY" --arg c "$RETENTION_CRON" '
      {kind: "doublestar", decoration: "repoMatches", pattern: "**"} as $all_repositories
      | {
        algorithm: "or",
        rules: [
          {disabled: false, action: "retain", template: "latestPushedK", params: {latestPushedK: $k},
            tag_selectors: [{kind: "doublestar", decoration: "matches", pattern: "**"}],
            scope_selectors: {repository: [$all_repositories]}},
          {disabled: false, action: "retain", template: "always", params: {},
            tag_selectors: [{kind: "doublestar", decoration: "matches", pattern: "sha256-*"}],
            scope_selectors: {repository: [$all_repositories]}}
        ],
        trigger: {kind: "Schedule", settings: {cron: $c}, references: {}},
        scope: {level: "project", ref: $ref}
      }' >/dev/null
    mv "$WORK/body.json" "$WORK/retention.json"
    if [ -z "$retention_id" ]; then
      expect 201 POST /retentions "$WORK/retention.json"
      changed "created the retention policy of $project"
      continue
    fi
    get "/retentions/$retention_id" >"$WORK/retention-live.json"
    if ! jq -e --slurpfile live "$WORK/retention-live.json" '
        def view: {algorithm, trigger: {kind: .trigger.kind, cron: .trigger.settings.cron},
          rules: [.rules[] | {disabled, action, template, params: (.params // {}),
            tags: [.tag_selectors[] | {decoration, pattern}],
            repositories: [.scope_selectors.repository[] | {decoration, pattern}]}]};
        view == ($live[0] | view)' "$WORK/retention.json" >/dev/null; then
      jq --argjson id "$retention_id" '. + {id: $id}' "$WORK/retention.json" >"$WORK/body.json"
      expect 200 PUT "/retentions/$retention_id" "$WORK/body.json"
      changed "updated the retention policy of $project"
    fi
  done
  finish
}

configure_webhooks() {
  local entry project current
  begin "webhooks"
  for entry in "${GOVERNED_PROJECTS[@]}"; do
    IFS='|' read -r project _ _ <<<"$entry"
    body --arg n "$WEBHOOK_NAME" --arg a "$WEBHOOK_ADDRESS" --argjson e "$WEBHOOK_EVENTS" '{
      name: $n, description: "Artifact events for dt-bridge", enabled: true, event_types: $e,
      targets: [{type: "http", address: $a, skip_cert_verify: false, payload_format: "Default"}]
    }' >/dev/null
    mv "$WORK/body.json" "$WORK/webhook.json"
    current="$(get "/projects/$project/webhook/policies" | jq -c --arg n "$WEBHOOK_NAME" '.[] | select(.name == $n)')"
    if [ -z "$current" ]; then
      expect 201 POST "/projects/$project/webhook/policies" "$WORK/webhook.json"
      changed "created webhook $WEBHOOK_NAME on $project"
      continue
    fi
    if ! jq -e --argjson live "$current" '
        def view: {description, enabled, events: (.event_types | sort),
          targets: [.targets[] | {type, address, skip_cert_verify, payload_format}]};
        view == ($live | view)' "$WORK/webhook.json" >/dev/null; then
      jq --argjson id "$(jq .id <<<"$current")" '. + {id: $id}' "$WORK/webhook.json" >"$WORK/body.json"
      expect 200 PUT "/projects/$project/webhook/policies/$(jq -r .id <<<"$current")" "$WORK/body.json"
      changed "updated webhook $WEBHOOK_NAME on $project"
    fi
  done
  finish
}

wait_for_harbor
configure_proxy_caches
configure_projects
configure_deployment_security
configure_replication
configure_robots
configure_immutability
configure_retention
configure_webhooks
