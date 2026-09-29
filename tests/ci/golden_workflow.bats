#!/usr/bin/env bats
# Golden build trigger, read statically from the workflow file.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
GOLDEN_WORKFLOW=.github/workflows/golden.yml

fail() {
  echo "$*" >&2
  return 1
}

@test "golden workflow publishes on pushes to main touching images/golden" {
  [ -f "$REPO_ROOT/$GOLDEN_WORKFLOW" ] || fail "$GOLDEN_WORKFLOW does not exist"
  push="$(yq -o=json '.on.push' "$REPO_ROOT/$GOLDEN_WORKFLOW")" || fail "$GOLDEN_WORKFLOW is not valid YAML"

  jq -e 'type == "object"' <<<"$push" >/dev/null || fail "$GOLDEN_WORKFLOW has no push trigger with filters: $push"
  jq -e '(.branches | type == "array") and (.branches | index("main") != null)' <<<"$push" >/dev/null ||
    fail "$GOLDEN_WORKFLOW push.branches does not list main: $(jq -c .branches <<<"$push")"
  jq -e '(.["branches-ignore"] // []) | index("main") == null' <<<"$push" >/dev/null ||
    fail "$GOLDEN_WORKFLOW ignores pushes to main"
  jq -e '(.paths | type == "array") and (.paths | index("images/golden/**") != null)' <<<"$push" >/dev/null ||
    fail "$GOLDEN_WORKFLOW push.paths does not list images/golden/**: $(jq -c .paths <<<"$push")"
}
