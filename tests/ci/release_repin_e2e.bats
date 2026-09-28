#!/usr/bin/env bats
# E2E catalog re-pin: release-repin-e2e.yml triggers, permissions and action pins, and
# `scripts/release-repin.sh e2e-params` run against a scratch git repository with a bare origin and a fake `gh`.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
WORKFLOW=.github/workflows/release-repin-e2e.yml
SCRIPT=scripts/release-repin.sh
FIXTURE_DOCKERFILES=(tests/fixtures/images/compliant/Dockerfile tests/fixtures/images/missing-labels/Dockerfile)
CHAINSAW_PARAMS=tests/chainsaw/params/golden-images.yaml
KYVERNO_CONTEXT=tests/kyverno/workload/context.yaml
GHCR=ghcr.io/naqa92-portfolio-projects/harborlab
NEW_PYTHON=sha256:1111111111111111111111111111111111111111111111111111111111111111
NEW_JAVA=sha256:2222222222222222222222222222222222222222222222222222222222222222

fail() {
  echo "$*" >&2
  return 1
}

git_quiet() {
  git -c user.name=test -c user.email=test@example.invalid -c init.defaultBranch=main "$@" >/dev/null 2>&1
}

# Scratch repository $WORK (branch main, pushed to the bare $ORIGIN) holding the script, the catalog and
# copies of the E2E files it re-pins; fake gh (argv appended to $FAKE_GH_LOG) first on $FAKE_PATH.
make_scratch_repo() {
  WORK="$BATS_TEST_TMPDIR/work"
  ORIGIN="$BATS_TEST_TMPDIR/origin.git"
  FAKE_PATH="$BATS_TEST_TMPDIR/bin"
  FAKE_GH_LOG="$BATS_TEST_TMPDIR/gh.log"
  mkdir -p "$WORK" "$FAKE_PATH"
  : >"$FAKE_GH_LOG"
  for path in "$SCRIPT" images/catalog.yaml "${FIXTURE_DOCKERFILES[@]}" "$CHAINSAW_PARAMS" "$KYVERNO_CONTEXT"; do
    mkdir -p "$WORK/$(dirname "$path")"
    cp "$REPO_ROOT/$path" "$WORK/$path"
  done

  cat >"$FAKE_PATH/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_GH_LOG"
EOF
  chmod +x "$FAKE_PATH/gh"

  git_quiet init --bare "$ORIGIN" || fail "cannot create the bare origin"
  git_quiet -C "$WORK" init || fail "cannot init the scratch repository"
  git_quiet -C "$WORK" add -A
  git_quiet -C "$WORK" commit -m "scratch main" || fail "cannot commit the scratch repository"
  git_quiet -C "$WORK" remote add origin "$ORIGIN"
  git_quiet -C "$WORK" push origin main || fail "cannot push the scratch main"
}

# Runs the scratch repository's `e2e-params` as workflow run $1 with the fake gh; sets status and output.
run_e2e_params() {
  run env PATH="$FAKE_PATH:$PATH" FAKE_GH_LOG="$FAKE_GH_LOG" GITHUB_RUN_ID="$1" "$WORK/$SCRIPT" e2e-params
}

origin_main() {
  git -C "$ORIGIN" rev-parse refs/heads/main
}

origin_branches() {
  git -C "$ORIGIN" for-each-ref --format='%(refname:short)' refs/heads | sort | paste -sd ' ' -
}

# "<key>: <value>" lines, in file order, of the golden-images data of the E2E params file $2 read from
# git revision $1 of $ORIGIN (or from the working file $2 when $1 is empty).
golden_entries() {
  local rev="$1" file="$2" content
  if [ -n "$rev" ]; then content="$(git -C "$ORIGIN" show "$rev:$file")"; else content="$(cat "$file")"; fi
  case "$file" in
    *"$CHAINSAW_PARAMS") yq '.data | to_entries | .[] | .key + ": " + .value' <<<"$content" ;;
    *) yq '.spec.resources[] | select(.metadata.name == "golden-images") | .data | to_entries | .[] | .key + ": " + .value' <<<"$content" ;;
  esac
}

@test "release-repin-e2e.yml runs on pushes to main touching an E2E pin or on dispatch, never on workflow_run" {
  [ -f "$REPO_ROOT/$WORKFLOW" ] || fail "$WORKFLOW does not exist"
  on="$(yq -o=json -I=0 '.on' "$REPO_ROOT/$WORKFLOW")" || fail "$WORKFLOW is not valid YAML"
  jq -e 'type == "object"' <<<"$on" >/dev/null || fail "$WORKFLOW .on is not a mapping: $on"
  jq -e 'has("workflow_run") | not' <<<"$on" >/dev/null || fail "$WORKFLOW triggers on workflow_run"
  jq -e 'has("pull_request_target") | not' <<<"$on" >/dev/null || fail "$WORKFLOW triggers on pull_request_target"
  jq -e 'has("pull_request") | not' <<<"$on" >/dev/null || fail "$WORKFLOW triggers on pull_request"
  jq -e 'has("workflow_dispatch")' <<<"$on" >/dev/null || fail "$WORKFLOW has no workflow_dispatch trigger"
  jq -e '.push.branches == ["main"]' <<<"$on" >/dev/null ||
    fail "$WORKFLOW push trigger is not limited to main: $(jq -c .push <<<"$on")"
  for path in images/catalog.yaml "${FIXTURE_DOCKERFILES[@]}" "$CHAINSAW_PARAMS" "$KYVERNO_CONTEXT" "$SCRIPT"; do
    jq -e --arg p "$path" '.push.paths | index($p) != null' <<<"$on" >/dev/null ||
      fail "$WORKFLOW push paths do not include $path: $(jq -c .push.paths <<<"$on")"
  done
  yq -e '.jobs[].steps[] | select((.run // "") | test("release-repin\.sh e2e-params"))' \
    "$REPO_ROOT/$WORKFLOW" >/dev/null 2>&1 || fail "no job of $WORKFLOW runs $SCRIPT e2e-params"
}

@test "release-repin-e2e.yml holds minimal permissions, pins actions by SHA and never pushes to main" {
  [ "$(yq -o=json -I=0 '.permissions' "$REPO_ROOT/$WORKFLOW")" = "{}" ] ||
    fail "$WORKFLOW top-level permissions are not {}: $(yq -o=json -I=0 '.permissions' "$REPO_ROOT/$WORKFLOW")"
  permissions="$(yq -o=json -I=0 '.jobs | with_entries(.value = .value.permissions)' "$REPO_ROOT/$WORKFLOW")"
  expected='{"e2e-params":{"contents":"write","pull-requests":"write"}}'
  jq -e --argjson want "$expected" '. == $want' <<<"$permissions" >/dev/null ||
    fail "$WORKFLOW job permissions are $permissions, expected $expected"

  uses="$(yq '[.jobs[].uses, .jobs[].steps[]?.uses] | .[] | select(. != null)' "$REPO_ROOT/$WORKFLOW")"
  [ -n "$uses" ] || fail "$WORKFLOW uses no action"
  unpinned="$(grep -vE '^[^@[:space:]]+@[0-9a-f]{40}$' <<<"$uses" || true)"
  [ -z "$unpinned" ] || fail "actions not pinned by commit SHA: $(paste -sd ' ' - <<<"$unpinned")"

  pushes="$(yq '.jobs[].steps[] | select((.run // "") | test("git[[:space:]]+push")) | .run' "$REPO_ROOT/$WORKFLOW")"
  [ -z "$pushes" ] || fail "$WORKFLOW pushes from a step instead of the script's pull request: $pushes"
}

@test "e2e-params does nothing while the E2E fixtures match the catalog" {
  make_scratch_repo
  main_before="$(origin_main)"

  run_e2e_params 4241
  [ "$status" -eq 0 ] || fail "e2e-params failed on the committed tree (exit $status): $output"
  [ "$(origin_main)" = "$main_before" ] || fail "e2e-params moved origin main"
  [ "$(origin_branches)" = main ] || fail "e2e-params pushed a branch with nothing to re-pin: $(origin_branches)"
  [ ! -s "$FAKE_GH_LOG" ] || fail "e2e-params called gh with nothing to re-pin: $(cat "$FAKE_GH_LOG")"
  [ -z "$(git -C "$WORK" status --porcelain)" ] || fail "e2e-params left changes: $(git -C "$WORK" status --porcelain)"
}

@test "e2e-params re-pins the E2E fixtures to the supported catalog digests, then does nothing" {
  make_scratch_repo
  yq -i "(.images[] | select(.name == \"python\" and .status == \"supported\") | .digest) = \"$NEW_PYTHON\"" \
    "$WORK/images/catalog.yaml"
  yq -i "(.images[] | select(.name == \"java\" and .status == \"supported\") | .digest) = \"$NEW_JAVA\"" \
    "$WORK/images/catalog.yaml"
  git_quiet -C "$WORK" commit -am "catalog moved on main"
  git_quiet -C "$WORK" push origin main
  main_before="$(origin_main)"

  run_e2e_params 4242
  [ "$status" -eq 0 ] || fail "e2e-params failed (exit $status): $output"
  branch=release-repin-e2e-params-4242
  [ "$(origin_main)" = "$main_before" ] || fail "e2e-params moved origin main ($main_before -> $(origin_main))"
  [ "$(origin_branches)" = "main $branch" ] || fail "origin branches are '$(origin_branches)', expected main and $branch"
  changed="$(git -C "$ORIGIN" diff --name-only main "$branch" | sort | paste -sd ' ' -)"
  expected_changed="$(printf '%s\n' "${FIXTURE_DOCKERFILES[@]}" "$CHAINSAW_PARAMS" "$KYVERNO_CONTEXT" | sort | paste -sd ' ' -)"
  [ "$changed" = "$expected_changed" ] || fail "$branch changes '$changed', expected '$expected_changed'"
  [ "$(wc -l <"$FAKE_GH_LOG")" -eq 1 ] || fail "gh was not called exactly once: $(cat "$FAKE_GH_LOG")"
  grep -qE "^pr create .*--base main .*--head $branch( |$)" "$FAKE_GH_LOG" ||
    fail "gh did not open a pull request from $branch to main: $(cat "$FAKE_GH_LOG")"

  for file in "${FIXTURE_DOCKERFILES[@]}"; do
    froms="$(git -C "$ORIGIN" show "$branch:$file" | grep -E '^FROM ')"
    [ "$froms" = "FROM $GHCR/golden/python@$NEW_PYTHON" ] ||
      fail "$file FROM lines are not the single golden/python@$NEW_PYTHON stage:"$'\n'"$froms"
  done

  # Supported entries follow images/catalog.yaml order (python, java); fixture-only deprecated/eol
  # entries, absent from the catalog, keep their committed digests.
  for file in "$CHAINSAW_PARAMS" "$KYVERNO_CONTEXT"; do
    entries="$(golden_entries "$branch" "$file")" || fail "$file on $branch is not valid YAML"
    supported="$(grep -E ': supported$' <<<"$entries")"
    [ "$supported" = "sha256.${NEW_PYTHON#sha256:}: supported"$'\n'"sha256.${NEW_JAVA#sha256:}: supported" ] ||
      fail "$file supported entries are not the catalog's, in order:"$'\n'"$supported"
    others="$(grep -vE ': supported$' <<<"$entries")"
    committed_others="$(golden_entries "" "$REPO_ROOT/$file" | grep -vE ': supported$')"
    [ -n "$committed_others" ] || fail "control: $file commits no deprecated/eol fixture entry"
    [ "$others" = "$committed_others" ] ||
      fail "$file fixture-only entries changed:"$'\n'"$others"$'\n'"expected:"$'\n'"$committed_others"
  done

  git_quiet -C "$WORK" checkout main || fail "cannot check out main"
  git_quiet -C "$WORK" merge --ff-only "$branch" || fail "cannot merge $branch"
  git_quiet -C "$WORK" push origin main || fail "cannot push the merged main"
  : >"$FAKE_GH_LOG"
  main_after="$(origin_main)"
  branches="$(origin_branches)"

  run_e2e_params 4243
  [ "$status" -eq 0 ] || fail "second run failed (exit $status): $output"
  [ "$(origin_main)" = "$main_after" ] || fail "second run moved origin main"
  [ "$(origin_branches)" = "$branches" ] || fail "second run pushed a branch: $(origin_branches)"
  [ ! -s "$FAKE_GH_LOG" ] || fail "second run called gh: $(cat "$FAKE_GH_LOG")"
  [ "$(git -C "$WORK" rev-parse --abbrev-ref HEAD)" = main ] || fail "second run left main"
  [ -z "$(git -C "$WORK" status --porcelain)" ] || fail "second run left changes: $(git -C "$WORK" status --porcelain)"
}
