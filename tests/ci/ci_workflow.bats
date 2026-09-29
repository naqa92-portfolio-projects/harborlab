#!/usr/bin/env bats
# ci.yml: the offline tests/ci and tests/docs bats suites run as a blocking job on every pull request and
# push to main; its bats steps are executed here with a fake `devbox` that records each invocation.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
WORKFLOW=.github/workflows/ci.yml
FORK_SKIPPED_TEST="DHI token value is not committed"

fail() {
  echo "$*" >&2
  return 1
}

# Runs every step of job $1 whose `run` calls bats, in order, from the repository root with IS_FORK_PR=$2
# and a fake devbox; invocation n's argv, one per line, lands in $CALLS/<n>. Sets status and output.
run_bats_steps() {
  local job="$1" fork="$2"
  FAKE_PATH="$BATS_TEST_TMPDIR/bin"
  CALLS="$BATS_TEST_TMPDIR/calls"
  STEPS="$BATS_TEST_TMPDIR/steps.sh"
  mkdir -p "$FAKE_PATH" "$CALLS"
  cat >"$FAKE_PATH/devbox" <<'EOF'
#!/usr/bin/env bash
n=$(find "$CALLS" -type f | wc -l)
printf '%s\n' "$@" >"$CALLS/$n"
EOF
  chmod +x "$FAKE_PATH/devbox"
  JOB="$job" yq '.jobs[strenv(JOB)].steps[] | select((.run // "") | test("bats")) | .run' "$REPO_ROOT/$WORKFLOW" >"$STEPS"
  [ -s "$STEPS" ] || fail "job $job of $WORKFLOW has no step running bats"
  run env -u DHI_TOKEN PATH="$FAKE_PATH:$PATH" CALLS="$CALLS" IS_FORK_PR="$fork" bash --noprofile --norc -eo pipefail -c "cd '$REPO_ROOT' && . '$STEPS'"
}

# Sorted, space-joined .bats paths passed to bats across every recorded invocation.
bats_files_run() {
  cat "$CALLS"/* | grep -E '\.bats$' | sort | paste -sd ' ' -
}

expected_files() {
  (cd "$REPO_ROOT" && find tests/ci tests/docs -maxdepth 1 -name '*.bats' | sort | paste -sd ' ' -)
}

@test "ci.yml runs on every pull request and on pushes to main, with minimal permissions and SHA-pinned actions" {
  [ -f "$REPO_ROOT/$WORKFLOW" ] || fail "$WORKFLOW does not exist"
  on="$(yq -o=json -I=0 '.on' "$REPO_ROOT/$WORKFLOW")" || fail "$WORKFLOW is not valid YAML"
  jq -e 'type == "object" and has("pull_request")' <<<"$on" >/dev/null || fail "$WORKFLOW does not run on pull_request: $on"
  jq -e '(.pull_request // {}) | has("paths") or has("paths-ignore") or has("branches") or has("branches-ignore") | not' \
    <<<"$on" >/dev/null || fail "$WORKFLOW pull_request trigger is filtered: $(jq -c .pull_request <<<"$on")"
  jq -e 'has("pull_request_target") | not' <<<"$on" >/dev/null || fail "$WORKFLOW triggers on pull_request_target"
  jq -e '.push.branches | index("main") != null' <<<"$on" >/dev/null ||
    fail "$WORKFLOW push trigger does not include main: $(jq -c .push <<<"$on")"
  jq -e '.push | has("paths") or has("paths-ignore") | not' <<<"$on" >/dev/null ||
    fail "$WORKFLOW push trigger is filtered by paths: $(jq -c .push <<<"$on")"

  [ "$(yq -o=json -I=0 '.permissions' "$REPO_ROOT/$WORKFLOW")" = "{}" ] ||
    fail "$WORKFLOW top-level permissions are not {}: $(yq -o=json -I=0 '.permissions' "$REPO_ROOT/$WORKFLOW")"
  permissions="$(yq -o=json -I=0 '.jobs | with_entries(.value = .value.permissions)' "$REPO_ROOT/$WORKFLOW")"
  jq -e 'to_entries | all(.value == {"contents":"read"})' <<<"$permissions" >/dev/null ||
    fail "$WORKFLOW job permissions are $permissions, expected contents: read only"

  uses="$(yq '[.jobs[].uses, .jobs[].steps[]?.uses] | .[] | select(. != null)' "$REPO_ROOT/$WORKFLOW")"
  [ -n "$uses" ] || fail "$WORKFLOW uses no action"
  unpinned="$(grep -vE '^[^@[:space:]]+@[0-9a-f]{40}$' <<<"$uses" || true)"
  [ -z "$unpinned" ] || fail "actions not pinned by commit SHA: $(paste -sd ' ' - <<<"$unpinned")"
}

@test "ci.yml bats job is blocking and sets up uv before the suites that lint dt-bridge through it" {
  jobs="$(yq '.jobs[] | select([.steps[]? | (.run // "") | test("bats")] | any) | key' "$REPO_ROOT/$WORKFLOW")"
  [ "$(wc -l <<<"$jobs")" -eq 1 ] && [ -n "$jobs" ] || fail "$WORKFLOW has not exactly one job running bats: $jobs"
  soft="$(JOB="$jobs" yq '[.jobs[strenv(JOB)], .jobs[strenv(JOB)].steps[]] | .[] | select(has("continue-on-error") or has("if")) | (.name // .run // "job")' "$REPO_ROOT/$WORKFLOW")"
  [ -z "$soft" ] || fail "job $jobs of $WORKFLOW has conditional or non-blocking parts: $soft"

  first_bats="$(JOB="$jobs" yq '.jobs[strenv(JOB)].steps | to_entries | map(select((.value.run // "") | test("bats"))) | .[0].key' "$REPO_ROOT/$WORKFLOW")"
  uv="$(JOB="$jobs" yq '.jobs[strenv(JOB)].steps | to_entries | map(select((.value.uses // "") | test("^astral-sh/setup-uv@"))) | .[0].key // ""' "$REPO_ROOT/$WORKFLOW")"
  [ -n "$uv" ] && [ "$uv" -lt "$first_bats" ] || fail "job $jobs does not set up uv (astral-sh/setup-uv) before its first bats step"
}

@test "ci.yml runs every tests/ci and tests/docs suite on a same-repository pull request, and nothing else" {
  run_bats_steps bats false
  [ "$status" -eq 0 ] || fail "bats steps failed (exit $status): $output"
  [ "$(bats_files_run)" = "$(expected_files)" ] ||
    fail "bats ran '$(bats_files_run)', expected '$(expected_files)'"
  ! grep -qE -- '^--(negative-)?filter' "$CALLS"/* || fail "a same-repository run filters tests: $(cat "$CALLS"/*)"
  for call in "$CALLS"/*; do
    [ "$(sed -n 1p "$call")" = "run" ] || fail "devbox invoked without run: $(paste -sd ' ' - <"$call")"
  done
}

@test "ci.yml on a fork pull request skips only the DHI token test, visibly" {
  [ "$(grep -cF "@test \"$FORK_SKIPPED_TEST\"" "$REPO_ROOT/tests/ci/secrets.bats")" -eq 1 ] ||
    fail "control: tests/ci/secrets.bats has no single test named '$FORK_SKIPPED_TEST'"
  [ "$(grep -c '@test ' "$REPO_ROOT/tests/ci/secrets.bats")" -gt 1 ] ||
    fail "control: tests/ci/secrets.bats has no other test left to run on a fork"
  fork_expr="$(yq '.jobs.bats.steps[] | select(.env.IS_FORK_PR != null) | .env.IS_FORK_PR' "$REPO_ROOT/$WORKFLOW")"
  grep -qF "github.event.pull_request.head.repo.full_name != github.repository" <<<"$fork_expr" ||
    fail "IS_FORK_PR does not compare the head repository with this one: $fork_expr"

  run_bats_steps bats true
  [ "$status" -eq 0 ] || fail "bats steps failed on a fork (exit $status): $output"
  [ "$(bats_files_run)" = "$(expected_files)" ] ||
    fail "bats ran '$(bats_files_run)' on a fork, expected '$(expected_files)'"
  filtered="$(grep -lE -- '^--(negative-)?filter' "$CALLS"/* || true)"
  [ "$(wc -w <<<"$filtered")" -eq 1 ] || fail "not exactly one filtered bats invocation on a fork: $(cat "$CALLS"/*)"
  [ "$(paste -sd ' ' - <"$filtered")" = "run -- bats --negative-filter $FORK_SKIPPED_TEST tests/ci/secrets.bats" ] ||
    fail "the fork invocation is not a negative filter on '$FORK_SKIPPED_TEST' alone: $(paste -sd ' ' - <"$filtered")"
  grep -qE "^::warning::.*$FORK_SKIPPED_TEST" <<<"$output" || fail "the fork skip emits no ::warning:: annotation: $output"
}
