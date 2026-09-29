#!/usr/bin/env bats
# OpenSSF Scorecard: one workflow runs ossf/scorecard-action on pushes to main and on a schedule, with
# least-privilege permissions, and publishes its results (Scorecard API and SARIF code scanning upload).

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
WORKFLOWS=.github/workflows
SCORECARD_ACTION=ossf/scorecard-action
UPLOAD_SARIF_ACTION=github/codeql-action/upload-sarif
# Scorecard needs these two, on its job only: SARIF upload and the OIDC token of publish_results.
JOB_WRITE_PERMISSIONS='{"id-token":"write","security-events":"write"}'
PIN_RE='^[^@[:space:]]+@[0-9a-f]{40}$'

fail() {
  echo "$*" >&2
  return 1
}

# Workflow files (repo-relative) with a step using $SCORECARD_ACTION, one per line.
scorecard_workflows() {
  local file
  for file in "$REPO_ROOT/$WORKFLOWS"/*.yml "$REPO_ROOT/$WORKFLOWS"/*.yaml; do
    [ -f "$file" ] || continue
    ACTION="$SCORECARD_ACTION" yq -e '.jobs[].steps[]? | select((.uses // "") | test("^" + strenv(ACTION) + "@"))' \
      "$file" >/dev/null 2>&1 && echo "${file#"$REPO_ROOT"/}"
  done
  return 0
}

@test "a workflow runs OpenSSF Scorecard on pushes to main and on a schedule, pinned by SHA" {
  workflows="$(scorecard_workflows)"
  [ -n "$workflows" ] || fail "no workflow under $WORKFLOWS runs $SCORECARD_ACTION (README and PRD Decision 16 cite OpenSSF Scorecard)"
  [ "$(wc -l <<<"$workflows")" -eq 1 ] || fail "several workflows run $SCORECARD_ACTION: $(paste -sd ' ' - <<<"$workflows")"
  workflow="$REPO_ROOT/$workflows"

  on="$(yq -o=json -I=0 '.on' "$workflow")"
  jq -e 'type == "object"' <<<"$on" >/dev/null || fail "$workflows .on is not a mapping: $on"
  jq -e '(.push.branches // []) | index("main") != null' <<<"$on" >/dev/null ||
    fail "$workflows does not run on push to main: $(jq -c '.push' <<<"$on")"
  jq -e '(.schedule // []) | length > 0 and all(.[]; (.cron // "") != "")' <<<"$on" >/dev/null ||
    fail "$workflows has no schedule trigger: $(jq -c '.schedule' <<<"$on")"
  jq -e 'has("pull_request_target") | not' <<<"$on" >/dev/null || fail "$workflows triggers on pull_request_target"

  uses="$(yq '[.jobs[].uses, .jobs[].steps[]?.uses] | .[] | select(. != null)' "$workflow")"
  unpinned="$(grep -vE "$PIN_RE" <<<"$uses" || true)"
  [ -z "$unpinned" ] || fail "$workflows actions not pinned by commit SHA: $(paste -sd ' ' - <<<"$unpinned")"
}

@test "the Scorecard workflow holds write permissions on its job only: id-token and security-events" {
  workflows="$(scorecard_workflows)"
  [ "$(wc -l <<<"$workflows")" -eq 1 ] && [ -n "$workflows" ] ||
    fail "expected exactly one workflow running $SCORECARD_ACTION, found '$(paste -sd ' ' - <<<"$workflows")'"
  workflow="$REPO_ROOT/$workflows"

  top="$(yq -o=json -I=0 '.permissions' "$workflow")"
  jq -e '. == "read-all" or (type == "object" and all(.[]; . == "read" or . == "none"))' <<<"$top" >/dev/null ||
    fail "$workflows top-level permissions grant more than read: $top"

  scorecard_job="$(ACTION="$SCORECARD_ACTION" yq -r '.jobs | to_entries[]
    | select([.value.steps[]?.uses // "" | test("^" + strenv(ACTION) + "@")] | any) | .key' "$workflow")"
  job_permissions="$(JOB="$scorecard_job" yq -o=json -I=0 '.jobs[strenv(JOB)].permissions' "$workflow")"
  jq -e --argjson want "$JOB_WRITE_PERMISSIONS" 'type == "object"
    and (with_entries(select(.value == "write")) == $want)
    and all(.[]; . == "write" or . == "read" or . == "none")' <<<"$job_permissions" >/dev/null ||
    fail "job $scorecard_job permissions are $job_permissions: expected write exactly on $(jq -c . <<<"$JOB_WRITE_PERMISSIONS"), read or none elsewhere"

  others="$(JOB="$scorecard_job" yq -o=json -I=0 '.jobs | to_entries[] | select(.key != strenv(JOB))
    | select((.value.permissions // {}) | (. == "write-all") or ((.["id-token"] // "") == "write") or ((.["security-events"] // "") == "write"))
    | .key' "$workflow")"
  [ -z "$others" ] || fail "jobs other than $scorecard_job grant id-token or security-events write: $(paste -sd ' ' - <<<"$others")"
}

@test "the Scorecard job publishes its results and uploads them as SARIF" {
  workflows="$(scorecard_workflows)"
  [ "$(wc -l <<<"$workflows")" -eq 1 ] && [ -n "$workflows" ] ||
    fail "expected exactly one workflow running $SCORECARD_ACTION, found '$(paste -sd ' ' - <<<"$workflows")'"
  workflow="$REPO_ROOT/$workflows"

  scorecard_job="$(ACTION="$SCORECARD_ACTION" yq -r '.jobs | to_entries[]
    | select([.value.steps[]?.uses // "" | test("^" + strenv(ACTION) + "@")] | any) | .key' "$workflow")"
  steps="$(JOB="$scorecard_job" yq -o=json -I=0 '.jobs[strenv(JOB)].steps' "$workflow")"
  scorecard="$(jq -c --arg a "$SCORECARD_ACTION@" 'to_entries[] | select((.value.uses // "") | startswith($a))' <<<"$steps")"
  jq -e '.value.with.publish_results == true' <<<"$scorecard" >/dev/null ||
    fail "job $scorecard_job does not set publish_results: true on $SCORECARD_ACTION: $(jq -c '.value.with' <<<"$scorecard")"
  jq -e '.value.with.results_format == "sarif"' <<<"$scorecard" >/dev/null ||
    fail "job $scorecard_job does not request SARIF results: $(jq -c '.value.with' <<<"$scorecard")"
  results_file="$(jq -r '.value.with.results_file // ""' <<<"$scorecard")"
  [ -n "$results_file" ] || fail "job $scorecard_job sets no results_file on $SCORECARD_ACTION"

  index="$(jq -r '.key' <<<"$scorecard")"
  jq -e --arg a "$UPLOAD_SARIF_ACTION@" --arg f "$results_file" --argjson i "$index" \
    '[to_entries[] | select(.key > $i and ((.value.uses // "") | startswith($a)) and .value.with.sarif_file == $f)] | length == 1' \
    <<<"$steps" >/dev/null ||
    fail "job $scorecard_job has no $UPLOAD_SARIF_ACTION step after Scorecard uploading sarif_file $results_file"
}
