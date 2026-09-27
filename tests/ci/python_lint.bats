#!/usr/bin/env bats
# dt-bridge Python hygiene: ruff lint and format pass on the app and its tests, and CI runs them with
# the pytest suite on the pull requests that touch the app.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
APP_DIR=apps/dt-bridge
WORKFLOWS_DIR=.github/workflows

fail() {
  echo "$*" >&2
  return 1
}

@test "ruff check and format pass on dt-bridge" {
  command -v uv >/dev/null || fail "uv is not on the PATH"
  cd "$REPO_ROOT/$APP_DIR"

  run uv run --frozen ruff check .
  [ "$status" -eq 0 ] || fail "ruff check fails on $APP_DIR (exit $status): $output"

  run uv run --frozen ruff format --check .
  [ "$status" -eq 0 ] || fail "ruff format --check fails on $APP_DIR (exit $status): $output"
}

@test "dt-bridge pytest and ruff run on pull requests touching the app" {
  found=""
  for workflow in "$REPO_ROOT/$WORKFLOWS_DIR"/*.y*ml; do
    json="$(yq -o=json '.' "$workflow")" || fail "$workflow is not valid YAML"
    # Triggered on every pull request touching the app: no branch filter, no paths-ignore covering it,
    # paths absent or listing apps/dt-bridge/** (or a broader apps/** pattern).
    jq -e '(.on // .true) as $on
      | ($on | if type == "object" then has("pull_request") elif type == "array" then index("pull_request") != null
          else . == "pull_request" end)
      and ($on | type != "object" or ((.pull_request // {}) as $pr
        | ($pr | has("branches") | not)
        and (($pr["paths-ignore"] // []) | all(.[]; test("^apps/(dt-bridge/)?\\*\\*$") | not))
        and (($pr.paths // null) == null or any($pr.paths[]; . == "apps/dt-bridge/**" or . == "apps/**"))))' \
      <<<"$json" >/dev/null || continue
    # One blocking job runs pytest, ruff check and ruff format --check on the app, each from a blocking step.
    jq -e '(.defaults.run["working-directory"] // "") as $top
      | [.jobs[] | select(.["continue-on-error"] != true)] | any(.[];
        (.defaults.run["working-directory"] // $top) as $job
        | [.steps[]? | select(.["continue-on-error"] != true)
          | select(((.["working-directory"] // $job) | test("(^|/)apps/dt-bridge/?$")) or ((.run // "") | test("apps/dt-bridge")))
          | .run // ""] as $runs
        | any($runs[]; test("(^|[^A-Za-z0-9_-])pytest([ \t]|$)"))
          and any($runs[]; test("ruff[ \t]+check"))
          and any($runs[]; test("ruff[ \t]+format[ \t]+--check")))' <<<"$json" >/dev/null && found+="${workflow##*/} "
  done
  [ -n "$found" ] ||
    fail "no workflow under $WORKFLOWS_DIR runs pytest, ruff check and ruff format --check on $APP_DIR in blocking steps of a blocking job on pull requests touching it"
}
