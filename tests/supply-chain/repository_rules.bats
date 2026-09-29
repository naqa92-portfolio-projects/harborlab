#!/usr/bin/env bats
# Branch rules of the GitHub repository, live through the GitHub API: one active ruleset on the default
# branch main blocks its deletion and force-pushes, and requires nothing else (no reviews, no status checks).

GITHUB_REPO=naqa92-portfolio-projects/harborlab
EXPECTED_RULES="deletion non_fast_forward"

fail() {
  echo "$*" >&2
  return 1
}

# Ids of the active branch rulesets defined on the repository itself, one per line.
active_repository_rulesets() {
  gh api "repos/$GITHUB_REPO/rulesets" \
    --jq '.[] | select(.source_type == "Repository" and .target == "branch" and .enforcement == "active") | .id'
}

# Ids of the active repository rulesets whose ref_name condition includes main, one per line.
rulesets_on_main() {
  local id
  for id in $(active_repository_rulesets); do
    gh api "repos/$GITHUB_REPO/rulesets/$id" \
      --jq 'select(.conditions.ref_name.include | any(. == "~DEFAULT_BRANCH" or . == "refs/heads/main")) | .id'
  done
}

@test "main is the default branch" {
  run gh api "repos/$GITHUB_REPO" --jq .default_branch
  [ "$status" -eq 0 ] || fail "cannot read repository $GITHUB_REPO: $output"
  [ "$output" = main ] || fail "the default branch of $GITHUB_REPO is '$output', not main"
}

@test "one active repository ruleset on main blocks exactly deletion and force-pushes" {
  run rulesets_on_main
  [ "$status" -eq 0 ] || fail "cannot read the rulesets of $GITHUB_REPO: $output"
  [ -n "$output" ] || fail "no active repository ruleset on main"
  [ "$(wc -l <<<"$output")" -eq 1 ] || fail "several active repository rulesets on main: $(tr '\n' ' ' <<<"$output")"
  ruleset_id="$output"

  run gh api "repos/$GITHUB_REPO/rulesets/$ruleset_id" --jq '[.rules[].type] | sort | join(" ")'
  [ "$status" -eq 0 ] || fail "cannot read ruleset $ruleset_id: $output"
  [ "$output" = "$EXPECTED_RULES" ] ||
    fail "ruleset $ruleset_id on main has rules '$output', expected exactly '$EXPECTED_RULES'"
}

@test "main requires no pull request review nor status check" {
  run gh api "repos/$GITHUB_REPO/rules/branches/main" --jq '[.[].type] | unique | join(" ")'
  [ "$status" -eq 0 ] || fail "cannot read the effective rules of main: $output"
  [ "$output" = "$EXPECTED_RULES" ] ||
    fail "effective rules of main are '${output:-none}', expected exactly '$EXPECTED_RULES'"
}
