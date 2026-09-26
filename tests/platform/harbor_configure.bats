#!/usr/bin/env bats
# `task harbor:configure` (OpenTofu) idempotence, live against the Harbor deployed by `task up`.
# Secrets are read at run time, sent only on stdin, and matched with output discarded.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
TOFU_STATE=tofu/harbor/terraform.tfstate
DHI_KV_PATH=platform/dhi
HARBOR_HOST=harbor.127.0.0.1.nip.io
HARBOR_NAMESPACE=harbor
HARBOR_ADMIN_SECRET=harbor-admin
HARBOR_DB_CLUSTER=harbor-db
HARBOR_DB_SECRET=harbor-db-credentials
OPENBAO_NAMESPACE=openbao
OPENBAO_POD=openbao-0
AUDIT_ROLE=platform-audit

# "<proxy-cache project>|<registry endpoint name>|<endpoint type>|<endpoint URL>"
PROXY_CACHES=(
  "dockerhub-proxy|dockerhub|docker-hub|https://hub.docker.com"
  "quay-proxy|quay|quay|https://quay.io"
  "ghcr-proxy|ghcr|github-ghcr|https://ghcr.io"
  "k8s-proxy|k8s|docker-registry|https://registry.k8s.io"
  "dhi-proxy|dhi|docker-registry|https://dhi.io"
)

# "<project>|<replication policy>|<GHCR name filter>"
GOVERNED_PROJECTS=(
  "golden|golden-from-ghcr|naqa92-portfolio-projects/harborlab/golden/**"
  "apps|apps-from-ghcr|naqa92-portfolio-projects/harborlab/apps/**"
)
REPLICATION_REGISTRY=ghcr

# dt-bridge arrives later; the webhook already targets its in-cluster address.
WEBHOOK_POLICY=dt-bridge
WEBHOOK_ADDRESS=http://dt-bridge.dt-bridge.svc.cluster.local:8080/harbor/events

# "<Harbor robot name>|<OpenBao KV path under secret/>"; fields `username` and `password`.
ROBOTS=(
  'robot$dt-bridge|platform/harbor-robot-dt-bridge'
)

fail() {
  echo "$*" >&2
  return 1
}

harbor_ca() {
  echo "$BATS_FILE_TMPDIR/harbor-ca.crt"
}

harbor_admin_password() {
  kubectl -n "$HARBOR_NAMESPACE" get secret "$HARBOR_ADMIN_SECRET" -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 -d
}

# Prints the body of an admin GET on the Harbor API; the Authorization header goes through stdin.
harbor_admin_json() {
  local path="$1" password body code
  password="$(harbor_admin_password)"
  [ -n "$password" ] || fail "Secret $HARBOR_NAMESPACE/$HARBOR_ADMIN_SECRET has no HARBOR_ADMIN_PASSWORD"
  body="$(mktemp "$BATS_FILE_TMPDIR/harbor-body.XXXXXX")"
  code="$(printf 'Authorization: Basic %s\n' "$(printf 'admin:%s' "$password" | base64 -w0)" |
    curl -sS --cacert "$(harbor_ca)" -H @- -o "$body" -w '%{http_code}' "https://$HARBOR_HOST/api/v2.0$path")"
  [ "$code" = 200 ] || fail "admin GET $path returned HTTP $code"
  cat "$body"
  rm -f "$body"
}

# HTTP status of the registry API root for the given credentials, sent on stdin. Harbor maps `/v2/`
# to its login check: 200 when authenticated, 401 otherwise (the token service would hand an
# anonymous token to bad credentials).
registry_login_status() {
  local username="$1" password="$2"
  printf 'Authorization: Basic %s\n' "$(printf '%s:%s' "$username" "$password" | base64 -w0)" |
    curl -sS --cacert "$(harbor_ca)" -H @- -o /dev/null -w '%{http_code}' "https://$HARBOR_HOST/v2/"
}

# Runs a shell script in the OpenBao container, logged in with the read-only audit role.
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

# Current KV v2 version of an OpenBao path; the full response is parsed here and never printed.
openbao_version() {
  openbao_audit 'bao kv get -mount=secret -format=json "$1"' "$1" 2>/dev/null | jq -r '.data.metadata.version'
}

openbao_field() {
  openbao_audit 'bao kv get -mount=secret -field="$2" "$1"' "$1" "$2"
}

# Runs a Taskfile task from the repository root; sets TASK_STATUS and TASK_LOG (stdout + stderr).
run_task() {
  TASK_LOG="$1"
  shift
  TASK_STATUS=0
  (cd "$REPO_ROOT" && task "$@") >"$TASK_LOG" 2>&1 || TASK_STATUS=$?
}

# Fails when the file contains the value; a test's own copy is deleted first so no secret remains.
refute_secret_in() {
  local file="$1" what="$2" label="$3" value="$4"
  [ -n "$value" ] || fail "$label is empty; cannot check $what"
  if grep -qF -f /dev/stdin "$file" <<<"$value"; then
    case "$file" in "$BATS_RUN_TMPDIR"/*) rm -f "$file" ;; esac
    fail "$what holds the $label"
  fi
}

refute_robot_secrets_in() {
  local file="$1" what="$2" entry name path
  for entry in "${ROBOTS[@]}"; do
    IFS='|' read -r name path <<<"$entry"
    refute_secret_in "$file" "$what" "secret of $name" "$(openbao_field "$path" password)"
  done
}

# Harbor admin password, robot secrets and the DHI token (the `dhi` endpoint credential).
refute_platform_secrets_in() {
  local file="$1" what="$2"
  refute_secret_in "$file" "$what" "Harbor admin password" "$(harbor_admin_password)"
  refute_robot_secrets_in "$file" "$what"
  refute_secret_in "$file" "$what" "DHI token" "$(openbao_field "$DHI_KV_PATH" token)"
}

# Decrypted state as `tofu show -json`, written mode 600; it holds sensitive values, never printed.
tofu_show_state() {
  local out="$1" err="$1.err" status=0
  (umask 077 && cd "$REPO_ROOT" && task harbor:tofu -- show -json) >"$out" 2>"$err" || status=$?
  refute_platform_secrets_in "$err" "task harbor:tofu -- show -json stderr"
  [ "$status" -eq 0 ] || {
    rm -f "$out"
    fail "task harbor:tofu -- show -json exited $status:"$'\n'"$(tail -n 20 "$err")"
  }
  jq -e . "$out" >/dev/null || {
    rm -f "$out"
    fail "task harbor:tofu -- show -json did not print JSON on stdout"
  }
}

# Managed resources of every module in a `tofu show -json` document.
MANAGED_RESOURCES='def mods: ., (.child_modules[]? | mods);
  [(.values.root_module // {}) | mods | .resources[]? | select(.mode == "managed")]'

# The state manages every category of the configuration contract; an empty plan is otherwise vacuous.
assert_state_manages_every_category() {
  local state="$1" entry project registry type url policy filter name path
  for entry in "${PROXY_CACHES[@]}"; do
    IFS='|' read -r project registry type url <<<"$entry"
    jq -e --arg r "$registry" "$MANAGED_RESOURCES"' | any(.[]; .type == "harbor_registry" and .values.name == $r)' \
      "$state" >/dev/null || fail "OpenTofu state manages no harbor_registry $registry"
    jq -e --arg p "$project" "$MANAGED_RESOURCES"' | any(.[]; .type == "harbor_project" and .values.name == $p)' \
      "$state" >/dev/null || fail "OpenTofu state manages no harbor_project $project (proxy cache)"
  done

  for entry in "${GOVERNED_PROJECTS[@]}"; do
    IFS='|' read -r project policy filter <<<"$entry"
    jq -e --arg p "$project" "$MANAGED_RESOURCES"' | any(.[]; .type == "harbor_project" and .values.name == $p
        and .values.deployment_security == "critical" and .values.vulnerability_scanning == true)' \
      "$state" >/dev/null ||
      fail "OpenTofu state manages no harbor_project $project with deployment_security=critical and vulnerability_scanning"
    for type in harbor_immutable_tag_rule harbor_retention_policy harbor_project_webhook; do
      jq -e --arg p "$project" --arg t "$type" "$MANAGED_RESOURCES"' as $r
        | ($r[] | select(.type == "harbor_project" and .values.name == $p) | .values.id) as $id
        | any($r[]; .type == $t and ((.values.project_id // .values.scope) == $id))' \
        "$state" >/dev/null || fail "OpenTofu state manages no $type for project $project"
    done
    jq -e --arg n "$policy" "$MANAGED_RESOURCES"' | any(.[]; .type == "harbor_replication" and .values.name == $n)' \
      "$state" >/dev/null || fail "OpenTofu state manages no harbor_replication $policy"
  done

  for entry in "${ROBOTS[@]}"; do
    IFS='|' read -r name path <<<"$entry"
    jq -e --arg n "$name" "$MANAGED_RESOURCES"' | any(.[]; .type == "harbor_robot_account" and .values.full_name == $n)' \
      "$state" >/dev/null || fail "OpenTofu state manages no harbor_robot_account $name"
  done
}

# Harbor served by ArgoCD with its database on CloudNativePG, credentials from External Secrets.
assert_harbor_on_cnpg() {
  local app cluster host
  app="$(kubectl -n argocd get applications.argoproj.io harbor -o json)" ||
    fail "ArgoCD Application harbor not found"
  [ "$(jq -r '"\(.status.sync.status) \(.status.health.status)"' <<<"$app")" = "Synced Healthy" ] ||
    fail "ArgoCD Application harbor is not Synced and Healthy: $(jq -c '{sync: .status.sync.status, health: .status.health.status}' <<<"$app")"

  cluster="$(kubectl -n "$HARBOR_NAMESPACE" get clusters.postgresql.cnpg.io "$HARBOR_DB_CLUSTER" -o json)" ||
    fail "CNPG Cluster $HARBOR_NAMESPACE/$HARBOR_DB_CLUSTER not found"
  [ "$(jq -r '.status.phase' <<<"$cluster")" = "Cluster in healthy state" ] ||
    fail "CNPG Cluster $HARBOR_DB_CLUSTER is not healthy: $(jq -r '.status.phase' <<<"$cluster")"
  [ "$(jq -r '.spec.instances' <<<"$cluster")" = 1 ] || fail "CNPG Cluster $HARBOR_DB_CLUSTER is not single-instance"
  [ "$(jq -r '.spec.bootstrap.initdb.secret.name' <<<"$cluster")" = "$HARBOR_DB_SECRET" ] ||
    fail "CNPG Cluster $HARBOR_DB_CLUSTER does not bootstrap its owner from Secret $HARBOR_DB_SECRET"

  host="$(kubectl -n "$HARBOR_NAMESPACE" get configmap harbor-core -o jsonpath='{.data.POSTGRESQL_HOST}')"
  [[ "$host" == "$HARBOR_DB_CLUSTER-rw" || "$host" == "$HARBOR_DB_CLUSTER-rw."* ]] ||
    fail "Harbor core uses database host '$host', not the CNPG service $HARBOR_DB_CLUSTER-rw"
}

# Normalised JSON of every object `task harbor:configure` manages, plus the OpenBao version of
# each robot secret (a regenerated secret is a change even though Harbor never returns it).
harbor_snapshot() {
  local out="$1" work project retention_id entry name path
  work="$(mktemp -d "$BATS_TEST_TMPDIR/snapshot.XXXXXX")"
  harbor_admin_json "/projects?page_size=100" >"$work/projects.json"
  harbor_admin_json "/registries?page_size=100" >"$work/registries.json"
  harbor_admin_json "/replication/policies?page_size=100" >"$work/replication.json"
  harbor_admin_json "/robots?page_size=100" >"$work/robots.json"

  echo '{}' >"$work/per-project.json"
  for project in $(jq -r '.[].name' "$work/projects.json"); do
    harbor_admin_json "/projects/$project/immutabletagrules" >"$work/immutable.json"
    harbor_admin_json "/projects/$project/webhook/policies" >"$work/webhooks.json"
    retention_id="$(jq -r --arg p "$project" '.[] | select(.name == $p) | .metadata.retention_id // ""' "$work/projects.json")"
    if [ -n "$retention_id" ]; then
      harbor_admin_json "/retentions/$retention_id" >"$work/retention.json"
    else
      echo null >"$work/retention.json"
    fi
    jq --arg p "$project" --slurpfile i "$work/immutable.json" --slurpfile w "$work/webhooks.json" \
      --slurpfile r "$work/retention.json" \
      '. + {($p): {immutable: ($i[0] | sort_by(.id)), webhooks: ($w[0] | sort_by(.name)), retention: $r[0]}}' \
      "$work/per-project.json" >"$work/per-project.next.json"
    mv "$work/per-project.next.json" "$work/per-project.json"
  done

  echo '{}' >"$work/openbao.json"
  for entry in "${ROBOTS[@]}"; do
    IFS='|' read -r name path <<<"$entry"
    jq --arg p "$path" --arg v "$(openbao_version "$path")" '. + {($p): $v}' "$work/openbao.json" >"$work/openbao.next.json"
    mv "$work/openbao.next.json" "$work/openbao.json"
  done

  jq -n -S --slurpfile projects "$work/projects.json" --slurpfile registries "$work/registries.json" \
    --slurpfile replication "$work/replication.json" --slurpfile robots "$work/robots.json" \
    --slurpfile per_project "$work/per-project.json" --slurpfile openbao "$work/openbao.json" '
    {
      projects: ($projects[0] | sort_by(.name)),
      registries: ($registries[0] | sort_by(.name)),
      replication: ($replication[0] | sort_by(.name)),
      # Harbor lists robot permissions and their access entries in no stable order: sets.
      robots: ($robots[0] | sort_by(.name)
        | map(.permissions |= (map(.access |= sort_by(.resource, .action)) | sort_by(.kind, .namespace)))),
      per_project: $per_project[0],
      openbao_robot_versions: $openbao[0]
    }
    | walk(if type == "object" then del(.creation_time, .update_time, .repo_count, .chart_count, .status) else . end)' \
    >"$out"
}

# The snapshot holds the configuration the contract names; otherwise "unchanged" would prove nothing.
assert_expected_configuration() {
  local snapshot="$1" entry project registry type url policy filter name path

  for entry in "${PROXY_CACHES[@]}"; do
    IFS='|' read -r project registry type url <<<"$entry"
    jq -e --arg r "$registry" --arg t "$type" --arg u "$url" \
      'any(.registries[]; .name == $r and .type == $t and .url == $u)' "$snapshot" >/dev/null ||
      fail "registry endpoint $registry ($type, $url) is missing"
    jq -e --arg p "$project" --arg r "$registry" '
      (.registries[] | select(.name == $r) | .id) as $id
      | any(.projects[]; .name == $p and .metadata.public == "true" and .registry_id == $id)' "$snapshot" >/dev/null ||
      fail "public proxy-cache project $project on registry $registry is missing"
  done

  for entry in "${GOVERNED_PROJECTS[@]}"; do
    IFS='|' read -r project policy filter <<<"$entry"
    jq -e --arg p "$project" '
      any(.projects[]; .name == $p and .metadata.public == "true" and ((.registry_id // 0) == 0))' "$snapshot" >/dev/null ||
      fail "public project $project (not a proxy cache) is missing"

    jq -e --arg p "$project" '
      any(.projects[]; .name == $p
        and .metadata.prevent_vul == "true" and .metadata.severity == "critical" and .metadata.auto_scan == "true")' \
      "$snapshot" >/dev/null ||
      fail "project $project lacks deployment security (prevent_vul=true, severity=critical, auto_scan=true)"

    jq -e --arg p "$project" '
      any(.per_project[$p].immutable[]?; (.disabled | not)
        and any(.scope_selectors.repository[]; .decoration == "repoMatches" and .pattern == "**")
        and any(.tag_selectors[]; .decoration == "excludes" and .pattern == "sha256-*"))' "$snapshot" >/dev/null ||
      fail "project $project has no enabled immutable rule on ** that excludes the sha256-* referrers tags"

    jq -e --arg p "$project" '
      .per_project[$p].retention as $r
      | $r != null and ($r.rules | length) > 0 and $r.trigger.kind == "Schedule" and (($r.trigger.settings.cron // "") != "")' \
      "$snapshot" >/dev/null ||
      fail "project $project has no scheduled retention policy with at least one rule"

    jq -e --arg p "$project" --arg n "$WEBHOOK_POLICY" --arg a "$WEBHOOK_ADDRESS" '
      any(.per_project[$p].webhooks[]?; .name == $n and .enabled
        and any(.targets[]; .type == "http" and .address == $a)
        and (.event_types | contains(["PUSH_ARTIFACT", "REPLICATION"])))' "$snapshot" >/dev/null ||
      fail "project $project has no enabled webhook $WEBHOOK_POLICY to $WEBHOOK_ADDRESS on PUSH_ARTIFACT and REPLICATION"

    jq -e --arg n "$policy" --arg p "$project" --arg f "$filter" --arg r "$REPLICATION_REGISTRY" '
      any(.replication[]; .name == $n and .enabled
        and .src_registry.name == $r and .dest_namespace == $p and .dest_namespace_replace_count == -1
        and .trigger.type == "scheduled"
        and any(.filters[]; .type == "name" and .value == $f)
        and ([.filters[] | select(.type == "tag")]
          | all(((.decoration // "matches") == "matches")
            and (.value | test("^\\*\\*$|(^|[{,])sha256-\\*([,}]|$)")))))' "$snapshot" >/dev/null ||
      fail "replication policy $policy ($REPLICATION_REGISTRY:$filter -> $project, flattened, scheduled, tags including sha256-*) is missing"
  done

  for entry in "${ROBOTS[@]}"; do
    IFS='|' read -r name path <<<"$entry"
    jq -e --arg n "$name" '
      any(.robots[]; .name == $n and .level == "system" and (.disable | not) and .duration == -1
        and ([.permissions[].namespace] | sort) == ["apps", "golden"]
        and all(.permissions[].access[]; .action == "pull" or .action == "read" or .action == "list"))' \
      "$snapshot" >/dev/null ||
      fail "robot $name (system, enabled, never expires, read-only on golden and apps) is missing"
    [[ "$(jq -r --arg p "$path" '.openbao_robot_versions[$p]' "$snapshot")" =~ ^[1-9][0-9]*$ ]] ||
      fail "OpenBao secret/$path holds no version of the $name credential"
  done
}

# Each robot's credential stored in OpenBao authenticates against Harbor, and a wrong one does not.
assert_robot_credentials_authenticate() {
  local entry name path username password code
  for entry in "${ROBOTS[@]}"; do
    IFS='|' read -r name path <<<"$entry"
    username="$(openbao_field "$path" username)"
    [ "$username" = "$name" ] || fail "OpenBao secret/$path username is '$username', expected $name"
    password="$(openbao_field "$path" password)"
    [ -n "$password" ] || fail "OpenBao secret/$path has no password"

    code="$(registry_login_status "$username" "$password")"
    [ "$code" = 200 ] || fail "Harbor GET /v2/ rejects the $name credential stored in OpenBao (HTTP $code)"
    code="$(registry_login_status "$username" "not-the-robot-secret")"
    [ "$code" = 401 ] || fail "Harbor GET /v2/ did not refuse a wrong secret for $name (HTTP $code); the check proves nothing"
  done
}

setup_file() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"

  assert_harbor_on_cnpg

  kubectl -n gateway get secret wildcard-nip-io-tls -o jsonpath='{.data.ca\.crt}' | base64 -d >"$(harbor_ca)"
  [ -s "$(harbor_ca)" ] || fail "Secret gateway/wildcard-nip-io-tls has no ca.crt"
  [ "$(curl -sS --cacert "$(harbor_ca)" "https://$HARBOR_HOST/api/v2.0/ping")" = Pong ] ||
    fail "Harbor does not answer on https://$HARBOR_HOST"

  run_task "$BATS_FILE_TMPDIR/configure-first.log" harbor:configure
  refute_platform_secrets_in "$TASK_LOG" "first task harbor:configure output"
  [ "$TASK_STATUS" -eq 0 ] ||
    fail "first task harbor:configure exited $TASK_STATUS:"$'\n'"$(tail -n 40 "$TASK_LOG")"
}

setup() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
}

@test "second harbor:configure run has an empty OpenTofu plan for every category" {
  # The plan a second run would apply, taken right after the first run.
  run_task "$BATS_TEST_TMPDIR/plan.log" harbor:plan
  refute_platform_secrets_in "$TASK_LOG" "task harbor:plan output"
  [ "$TASK_STATUS" -eq 0 ] ||
    fail "OpenTofu plan after a first harbor:configure is not empty: task harbor:plan exited $TASK_STATUS (tofu plan -detailed-exitcode: 2 = changes pending):"$'\n'"$(tail -n 40 "$TASK_LOG")"

  run_task "$BATS_TEST_TMPDIR/configure-second.log" harbor:configure
  refute_platform_secrets_in "$TASK_LOG" "second task harbor:configure output"
  [ "$TASK_STATUS" -eq 0 ] ||
    fail "second task harbor:configure exited $TASK_STATUS:"$'\n'"$(tail -n 40 "$TASK_LOG")"

  tofu_show_state "$BATS_TEST_TMPDIR/state.json"
  assert_state_manages_every_category "$BATS_TEST_TMPDIR/state.json"
  rm -f "$BATS_TEST_TMPDIR/state.json"
}

@test "second harbor:configure run leaves Harbor state unchanged" {
  harbor_snapshot "$BATS_TEST_TMPDIR/before.json"
  assert_expected_configuration "$BATS_TEST_TMPDIR/before.json"

  run_task "$BATS_TEST_TMPDIR/configure-again.log" harbor:configure
  refute_platform_secrets_in "$TASK_LOG" "task harbor:configure output"
  [ "$TASK_STATUS" -eq 0 ] ||
    fail "task harbor:configure exited $TASK_STATUS on an already configured Harbor:"$'\n'"$(tail -n 40 "$TASK_LOG")"

  harbor_snapshot "$BATS_TEST_TMPDIR/after.json"
  run diff -u "$BATS_TEST_TMPDIR/before.json" "$BATS_TEST_TMPDIR/after.json"
  [ "$status" -eq 0 ] || fail "task harbor:configure changed Harbor state on a second run:"$'\n'"$output"

  assert_robot_credentials_authenticate
}

@test "OpenTofu state is git-ignored, encrypted by OpenBao Transit and holds no robot secret" {
  local file state="$REPO_ROOT/$TOFU_STATE"
  [ -s "$state" ] || fail "no OpenTofu state at $TOFU_STATE after task harbor:configure"

  for file in "$TOFU_STATE" "$TOFU_STATE.backup"; do
    [ -e "$REPO_ROOT/$file" ] || continue
    git -C "$REPO_ROOT" check-ignore -q "$file" || fail "$file is not git-ignored"
    ! git -C "$REPO_ROOT" ls-files --error-unmatch "$file" >/dev/null 2>&1 || fail "$file is tracked by git"
    jq -e '(has("resources") | not) and (.encrypted_data | type == "string")
      and (.encryption_version | type == "string")
      and any(.meta | keys[]; startswith("key_provider.openbao."))' "$REPO_ROOT/$file" >/dev/null 2>&1 ||
      fail "$file is not an OpenTofu payload encrypted by an openbao key provider (plain resources, or no key_provider.openbao.* metadata)"
    refute_platform_secrets_in "$REPO_ROOT/$file" "$file"
  done

  run openbao_audit 'bao secrets list -format=json'
  [ "$status" -eq 0 ] || fail "cannot list OpenBao mounts with role $AUDIT_ROLE: $output"
  jq -e '."transit/".type == "transit"' <<<"$output" >/dev/null ||
    fail "OpenBao has no Transit engine mounted at transit/ for the state key"

  tofu_show_state "$BATS_TEST_TMPDIR/state.json"
  jq -e "$MANAGED_RESOURCES"' | [.[] | select(.type == "harbor_robot_account")]
    | length > 0 and all(.[]; (.values.secret // "") == "")' "$BATS_TEST_TMPDIR/state.json" >/dev/null ||
    fail "decrypted OpenTofu state has no harbor_robot_account, or one holds a secret value (use secret_wo)"
  refute_robot_secrets_in "$BATS_TEST_TMPDIR/state.json" "decrypted OpenTofu state"
  rm -f "$BATS_TEST_TMPDIR/state.json"
}
