#!/usr/bin/env bats
# Platform reliability, live against the cluster started by `task up`: the runtime demo on freshly recreated
# pods, VictoriaLogs memory, Harbor retention of pinned digests and the demo fixtures replication.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
load dt

RUNTIME_DEMO=runtime-demo/runtime-demo
RUNTIME_SHELL_RUNS=3
RUNTIME_SHELL_TIMEOUT_SECONDS=180
ROLLOUT_TIMEOUT=180s
VICTORIA_LOGS_POD=observability/victoria-logs-0
VICTORIA_LOGS_MIN_LIMIT_MI=512
CATALOG=images/catalog.yaml
WORKLOAD_MANIFESTS=platform/workloads
HARBOR_IMAGE_RE='harbor\.127\.0\.0\.1\.nip\.io/(golden|apps)/([a-z0-9._/-]+)@(sha256:[0-9a-f]{64})'
FIXTURES_REPLICATION=apps-demo-fixtures-from-ghcr

fail() {
  echo "$*" >&2
  return 1
}

setup_file() {
  dt_setup_file
}

setup() {
  dt_setup
}

memory_mi() {
  local value="$1"
  case "$value" in
    *Gi) echo $((${value%Gi} * 1024)) ;;
    *Mi) echo "${value%Mi}" ;;
    *G) echo $((${value%G} * 1000 * 1000 * 1000 / 1048576)) ;;
    *M) echo $((${value%M} * 1000 * 1000 / 1048576)) ;;
    *) echo 0 ;;
  esac
}

# Every digest the platform pins in Harbor, one "<project>|<repository>|<digest>" per line: the catalog
# golden images and the images of the workload manifests.
pinned_digests() {
  yq -r '.images[] | "golden|" + .name + "|" + .digest' "$REPO_ROOT/$CATALOG"
  grep -rhoE "$HARBOR_IMAGE_RE" "$REPO_ROOT/$WORKLOAD_MANIFESTS" | sort -u |
    sed -E "s#^$HARBOR_IMAGE_RE\$#\\1|\\2|\\3#"
}

@test "demo:runtime-shell succeeds on a just-recreated runtime-demo pod, three times in a row" {
  for run in $(seq 1 "$RUNTIME_SHELL_RUNS"); do
    kubectl -n "${RUNTIME_DEMO%/*}" rollout restart "deployment/${RUNTIME_DEMO#*/}" >/dev/null
    kubectl -n "${RUNTIME_DEMO%/*}" rollout status "deployment/${RUNTIME_DEMO#*/}" --timeout="$ROLLOUT_TIMEOUT" >/dev/null ||
      fail "run $run: deployment $RUNTIME_DEMO did not roll out within $ROLLOUT_TIMEOUT"
    # Once, no retry: the first shell on the recreated pod must raise the alert.
    run timeout "$RUNTIME_SHELL_TIMEOUT_SECONDS" bash -c 'cd "$1" && exec task demo:runtime-shell' _ "$REPO_ROOT"
    [ "$status" -eq 0 ] ||
      fail "run $run of $RUNTIME_SHELL_RUNS: demo:runtime-shell exited $status on a just-recreated pod: $(tail -n 3 <<<"$output" | paste -sd ' ' -)"
    grep -qE '^runtime-shell alert: .+' <<<"$output" ||
      fail "run $run: demo:runtime-shell exited 0 without printing the alert it observed"
  done
}

@test "VictoriaLogs runs with at least 512Mi and was never OOMKilled" {
  run kubectl -n "${VICTORIA_LOGS_POD%/*}" get pod "${VICTORIA_LOGS_POD#*/}" -o json
  [ "$status" -eq 0 ] || fail "pod $VICTORIA_LOGS_POD not found: $output"
  pod="$output"
  limit="$(jq -r '[.spec.containers[] | select(.name | test("vlogs|victoria"))][0].resources.limits.memory // ""' <<<"$pod")"
  [ -n "$limit" ] || fail "pod $VICTORIA_LOGS_POD has no memory limit"
  [ "$(memory_mi "$limit")" -ge "$VICTORIA_LOGS_MIN_LIMIT_MI" ] ||
    fail "pod $VICTORIA_LOGS_POD memory limit $limit is below ${VICTORIA_LOGS_MIN_LIMIT_MI}Mi"
  killed="$(jq -r '.status.containerStatuses[] | select(.lastState.terminated.reason == "OOMKilled")
    | "\(.name) (restarts \(.restartCount), last \(.lastState.terminated.finishedAt))"' <<<"$pod")"
  [ -z "$killed" ] || fail "VictoriaLogs was OOMKilled: $killed"
}

@test "Harbor retention always keeps every digest pinned by the catalog and the workload manifests" {
  # Doublestar pattern as Harbor's retention selectors read it, as an anchored regexp.
  glob_regex='def glob_regex: "^" + (gsub("(?<c>[.+^$()|\\[\\]\\\\])"; "\\\(.c)")
    | gsub("\\*\\*"; "\u0001") | gsub("\\*"; "[^/]*") | gsub("\\?"; ".") | gsub("\u0001"; ".*")
    | gsub("\\{(?<alts>[^}]*)\\}"; "(" + (.alts | gsub(","; "|")) + ")")) + "$";'
  declare -A rules
  while IFS='|' read -r project repository digest; do
    [ -n "$project" ] || continue
    if [ -z "${rules[$project]:-}" ]; then
      harbor_admin GET "/projects/$project"
      [ "$HTTP_CODE" = 200 ] || fail "cannot read Harbor project $project (HTTP $HTTP_CODE)"
      retention="$(jq -r '.metadata.retention_id // ""' "$HTTP_BODY")"
      [ -n "$retention" ] || fail "Harbor project $project has no retention policy"
      harbor_admin GET "/retentions/$retention"
      [ "$HTTP_CODE" = 200 ] || fail "cannot read retention policy $retention (HTTP $HTTP_CODE)"
      rules[$project]="$(jq -c '[.rules[] | select(.disabled != true and .action == "retain" and .template == "always")]' "$HTTP_BODY")"
    fi
    harbor_admin GET "/projects/$project/repositories/${repository//\//%252F}/artifacts/$digest?with_tag=true"
    [ "$HTTP_CODE" = 200 ] || fail "Harbor has no $project/$repository@$digest (HTTP $HTTP_CODE)"
    tags="$(jq -c '[.tags[]?.name]' "$HTTP_BODY")"
    kept="$(jq -rn --argjson rules "${rules[$project]}" --argjson tags "$tags" --arg repo "$repository" "$glob_regex"'
      def selected($selectors; $value; $match; $exclude):
        ($selectors | map(select(.decoration == $match))) as $m
        | ($selectors | map(select(.decoration == $exclude))) as $x
        | (($m | length) == 0 or any($m[]; .pattern as $p | $value | test($p | glob_regex)))
          and all($x[]; .pattern as $p | $value | test($p | glob_regex) | not);
      any($rules[]; . as $rule
        | selected($rule.scope_selectors.repository // []; $repo; "repoMatches"; "repoExcludes")
        and any($tags[]; . as $tag | selected($rule.tag_selectors // []; $tag; "matches"; "excludes")))')"
    [ "$kept" = true ] ||
      fail "no always-retain rule of Harbor project $project keeps $repository@$digest (tags $tags): the next retention run can delete a pinned image"
  done < <(pinned_digests)
}

@test "the latest demo fixtures replication succeeded" {
  harbor_admin GET "/replication/policies?name=$FIXTURES_REPLICATION"
  [ "$HTTP_CODE" = 200 ] || fail "cannot list replication policies (HTTP $HTTP_CODE)"
  policy="$(jq -r --arg n "$FIXTURES_REPLICATION" '.[] | select(.name == $n) | .id' "$HTTP_BODY")"
  [ -n "$policy" ] || fail "replication policy $FIXTURES_REPLICATION not found"
  harbor_admin GET "/replication/executions?policy_id=$policy&page_size=1&sort=-start_time"
  [ "$HTTP_CODE" = 200 ] || fail "cannot list the executions of $FIXTURES_REPLICATION (HTTP $HTTP_CODE)"
  latest="$(jq -r '.[0] | "\(.id) \(.status) \(.start_time) \(.trigger)"' "$HTTP_BODY")"
  [ "$latest" != "null null null null" ] || fail "replication $FIXTURES_REPLICATION never ran"
  read -r id status started trigger <<<"$latest"
  case "$status" in
    Succeed | Success) ;;
    *) fail "the latest execution $id of $FIXTURES_REPLICATION ($trigger, $started) ended $status" ;;
  esac
}
