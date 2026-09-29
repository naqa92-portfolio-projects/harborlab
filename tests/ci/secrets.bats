#!/usr/bin/env bats
# No secret in Git. Findings are reported redacted; the DHI token is only ever a grep pattern
# read from stdin, so it reaches neither argv nor output.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"

fail() {
  echo "$*" >&2
  return 1
}

gitleaks_config_args() {
  if [ -f "$REPO_ROOT/.gitleaks.toml" ]; then
    printf '%s\n' --config "$REPO_ROOT/.gitleaks.toml"
  fi
}

# Scans every commit reachable from any ref of repository $1; the redacted JSON report lands in $2.
gitleaks_history() {
  local config_args
  mapfile -t config_args < <(gitleaks_config_args)
  gitleaks git --no-banner --redact --log-level error --log-opts=--all \
    "${config_args[@]}" --report-format json --report-path "$2" "$1" >/dev/null 2>&1
}

# True when the pattern read on stdin appears in a tracked file of any commit or in a commit message.
repo_contains_stdin_pattern() {
  local repo="$1" pattern_file="$BATS_TEST_TMPDIR/pattern"
  (umask 077 && cat >"$pattern_file")
  local found=1
  mapfile -t revisions < <(git -C "$repo" rev-list --all)
  if [ "${#revisions[@]}" -gt 0 ] &&
    { git -C "$repo" grep -qF -f "$pattern_file" "${revisions[@]}" -- ||
      git -C "$repo" log --all --format=%B | grep -qF -f "$pattern_file"; }; then
    found=0
  fi
  rm -f "$pattern_file"
  return "$found"
}

make_temp_repo() {
  git init -q "$1"
  git -C "$1" config user.email tests@example.invalid
  git -C "$1" config user.name tests
}

@test "git history holds no secret" {
  [ "$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository)" = false ] ||
    fail "shallow clone: the full history is required (fetch-depth: 0)"

  control="$BATS_TEST_TMPDIR/control-repo"
  make_temp_repo "$control"
  printf 'GITHUB_TOKEN=%s\n' "ghp_""8fK2mQ9xLr4TzW7vNc1bY6hJ3dS5gPa0eUoI" >"$control/leak.env"
  git -C "$control" add leak.env
  git -C "$control" commit -qm "fixture: leaked token"
  command -v gitleaks >/dev/null || fail "gitleaks is not on the devbox PATH"
  run gitleaks_history "$control" "$BATS_TEST_TMPDIR/control-report.json"
  [ "$status" -eq 1 ] && [ "$(jq length "$BATS_TEST_TMPDIR/control-report.json")" -ge 1 ] ||
    fail "gitleaks missed a committed GitHub token in the control repository (exit $status)"

  run gitleaks_history "$REPO_ROOT" "$BATS_TEST_TMPDIR/report.json"
  [ -f "$BATS_TEST_TMPDIR/report.json" ] || fail "gitleaks did not produce a report on the repository (exit $status)"
  if [ "$status" -ne 0 ]; then
    fail "gitleaks found secrets in the git history (exit $status):"$'\n'"$(
      jq -r '.[]? | "\(.RuleID) \(.Commit[0:12]) \(.File):\(.StartLine)"' "$BATS_TEST_TMPDIR/report.json" 2>/dev/null
    )"
  fi
}

@test "DHI token value is not committed" {
  [ -n "${DHI_TOKEN:-}" ] || fail "DHI_TOKEN is not set in the environment"
  [ "${#DHI_TOKEN}" -ge 16 ] || fail "DHI_TOKEN is shorter than 16 characters; a match would be meaningless"

  control="$BATS_TEST_TMPDIR/control-repo"
  make_temp_repo "$control"
  printf 'token: fake-dhi-token-for-tests\n' >"$control/config.yaml"
  git -C "$control" add config.yaml
  git -C "$control" commit -qm "fixture"
  repo_contains_stdin_pattern "$control" <<<"fake-dhi-token-for-tests" ||
    fail "the history search missed a committed value in the control repository"

  ! repo_contains_stdin_pattern "$REPO_ROOT" <<<"$DHI_TOKEN" ||
    fail "the DHI_TOKEN value appears in a commit of this repository"
}
