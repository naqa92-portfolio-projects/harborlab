#!/usr/bin/env bats
# Branch rules of the GitHub repository, live through the GitHub API: the signing identity trusts
# build-image.yml on main, so main only changes through reviewed pull requests, and prd-* branches, which
# sign images for their own platform deployment, cannot be created by anyone with push access.

GITHUB_REPO=naqa92-portfolio-projects/harborlab
PROBE_BRANCH=prd-999-ruleset-probe

fail() {
  echo "$*" >&2
  return 1
}

# Rule types GitHub enforces on branch $1 (rulesets and branch protection alike), one per line.
effective_rules() {
  gh api "repos/$GITHUB_REPO/rules/branches/$1" --jq '.[].type' 2>&1
}

@test "main can neither be force-pushed, deleted nor changed without a pull request" {
  run effective_rules main
  [ "$status" -eq 0 ] || fail "cannot read the rules of main: $output"
  for rule in non_fast_forward deletion pull_request; do
    grep -qx "$rule" <<<"$output" || fail "main is not protected by a '$rule' rule (effective rules: $(tr '\n' ' ' <<<"$output"))"
  done
}

@test "prd-* branches cannot be created without bypass" {
  run effective_rules "$PROBE_BRANCH"
  [ "$status" -eq 0 ] || fail "cannot read the rules of $PROBE_BRANCH: $output"
  grep -qx creation <<<"$output" ||
    fail "a new branch $PROBE_BRANCH is not restricted by a 'creation' rule (effective rules: $(tr '\n' ' ' <<<"$output"))"
}
