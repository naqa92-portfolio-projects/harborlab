#!/usr/bin/env bats
# Post-merge re-pin: release-repin.yml triggers, permissions and action pins, and scripts/release-repin.sh
# run against a scratch git repository with a bare origin, a fake `crane` registry and a fake `gh`.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
WORKFLOW=.github/workflows/release-repin.yml
SCRIPT=scripts/release-repin.sh
APP_DOCKERFILES=(apps/dt-bridge/Dockerfile apps/hello-java/Dockerfile apps/runtime-demo/Dockerfile)
WORKLOADS=(platform/workloads/dt-bridge/dt-bridge.yaml platform/workloads/hello-java/hello-java.yaml
  platform/workloads/runtime-demo/runtime-demo.yaml)
DEMO_FIXTURES=images/demo-fixtures.yaml
GHCR=ghcr.io/naqa92-portfolio-projects/harborlab
NEW_PYTHON=sha256:1111111111111111111111111111111111111111111111111111111111111111
NEW_JAVA=sha256:2222222222222222222222222222222222222222222222222222222222222222
NEW_HELLO_JAVA=sha256:3333333333333333333333333333333333333333333333333333333333333333
NEW_DT_BRIDGE=sha256:4444444444444444444444444444444444444444444444444444444444444444
NEW_RUNTIME_DEMO=sha256:5555555555555555555555555555555555555555555555555555555555555555
NEW_FIXTURE=sha256:6666666666666666666666666666666666666666666666666666666666666666
MAIN_SHA=0123456789abcdef0123456789abcdef01234567
E2E_FILES=(tests/fixtures/images/compliant/Dockerfile tests/fixtures/images/missing-labels/Dockerfile
  tests/chainsaw/params/golden-images.yaml tests/kyverno/workload/context.yaml)
# A waiting job's timeout covers the script's wait plus checkout, devbox install and registry login.
JOB_SETUP_SECONDS=300
# GitHub Actions' timeout-minutes when a job sets none.
DEFAULT_JOB_TIMEOUT_MINUTES=360

fail() {
  echo "$*" >&2
  return 1
}

git_quiet() {
  git -c user.name=test -c user.email=test@example.invalid -c init.defaultBranch=main "$@" >/dev/null 2>&1
}

# Scratch repository $WORK (branch main, pushed to the bare $ORIGIN) holding the script and copies of
# the files it re-pins; fake crane (digests from $FAKE_REGISTRY, "<ref> <digest>" lines) and gh (argv
# appended to $FAKE_GH_LOG) first on $FAKE_PATH.
make_scratch_repo() {
  WORK="$BATS_TEST_TMPDIR/work"
  ORIGIN="$BATS_TEST_TMPDIR/origin.git"
  FAKE_PATH="$BATS_TEST_TMPDIR/bin"
  FAKE_REGISTRY="$BATS_TEST_TMPDIR/registry"
  FAKE_GH_LOG="$BATS_TEST_TMPDIR/gh.log"
  mkdir -p "$WORK" "$FAKE_PATH"
  : >"$FAKE_REGISTRY"
  : >"$FAKE_GH_LOG"
  for path in "$SCRIPT" images/catalog.yaml "$DEMO_FIXTURES" "${APP_DOCKERFILES[@]}" "${WORKLOADS[@]}"; do
    mkdir -p "$WORK/$(dirname "$path")"
    cp "$REPO_ROOT/$path" "$WORK/$path"
  done

  cat >"$FAKE_PATH/crane" <<'EOF'
#!/usr/bin/env bash
[ "$1" = digest ] || { echo "fake crane: unsupported command: $*" >&2; exit 2; }
digest="$(awk -v ref="$2" '$1 == ref { print $2 }' "$FAKE_REGISTRY")"
[ -n "$digest" ] || { echo "GET $2: MANIFEST_UNKNOWN: manifest unknown" >&2; exit 1; }
echo "$digest"
EOF
  cat >"$FAKE_PATH/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_GH_LOG"
EOF
  chmod +x "$FAKE_PATH/crane" "$FAKE_PATH/gh"

  git_quiet init --bare "$ORIGIN" || fail "cannot create the bare origin"
  git_quiet -C "$WORK" init || fail "cannot init the scratch repository"
  git_quiet -C "$WORK" add -A
  git_quiet -C "$WORK" commit -m "scratch main" || fail "cannot commit the scratch repository"
  git_quiet -C "$WORK" remote add origin "$ORIGIN"
  git_quiet -C "$WORK" push origin main || fail "cannot push the scratch main"
}

# Runs the scratch repository's script as workflow run $1 with the fakes; sets status and output.
run_repin() {
  local run_id="$1"
  shift
  run env PATH="$FAKE_PATH:$PATH" FAKE_REGISTRY="$FAKE_REGISTRY" FAKE_GH_LOG="$FAKE_GH_LOG" GITHUB_RUN_ID="$run_id" \
    RELEASE_REPIN_TIMEOUT=0 RELEASE_REPIN_INTERVAL=1 "$WORK/$SCRIPT" "$@"
}

origin_main() {
  git -C "$ORIGIN" rev-parse refs/heads/main
}

origin_branches() {
  git -C "$ORIGIN" for-each-ref --format='%(refname:short)' refs/heads | sort | paste -sd ' ' -
}

# Asserts that the last run pushed exactly branch $1 (main untouched at $2), that it changes exactly the
# files $3.. against main, and that gh opened one pull request from it to main.
assert_repin_pr() {
  local branch="$1" main_before="$2"
  shift 2
  [ "$(origin_main)" = "$main_before" ] || fail "the script moved origin main ($main_before -> $(origin_main))"
  [ "$(origin_branches)" = "$(printf '%s\n' main "$branch" | sort | paste -sd ' ' -)" ] ||
    fail "origin branches are '$(origin_branches)', expected main and $branch"
  changed="$(git -C "$ORIGIN" diff --name-only main "$branch" | sort | paste -sd ' ' -)"
  [ "$changed" = "$(printf '%s\n' "$@" | sort | paste -sd ' ' -)" ] ||
    fail "$branch changes '$changed', expected '$*'"
  [ "$(wc -l <"$FAKE_GH_LOG")" -eq 1 ] || fail "gh was not called exactly once: $(cat "$FAKE_GH_LOG")"
  grep -qE "^pr create .*--base main .*--head $branch( |$)" "$FAKE_GH_LOG" ||
    fail "gh did not open a pull request from $branch to main: $(cat "$FAKE_GH_LOG")"
}

# Merges $1 into the scratch main and pushes it, as merging the re-pin pull request does.
merge_repin_pr() {
  git_quiet -C "$WORK" checkout main || fail "cannot check out main"
  git_quiet -C "$WORK" merge --ff-only "$1" || fail "cannot merge $1"
  git_quiet -C "$WORK" push origin main || fail "cannot push the merged main"
  : >"$FAKE_GH_LOG"
}

# Asserts that the last run, on main after the merge, changed nothing and opened nothing.
assert_noop() {
  local main_before="$1" branches_before="$2"
  [ "$status" -eq 0 ] || fail "second run failed (exit $status): $output"
  [ "$(origin_main)" = "$main_before" ] || fail "second run moved origin main"
  [ "$(origin_branches)" = "$branches_before" ] || fail "second run pushed a branch: $(origin_branches)"
  [ ! -s "$FAKE_GH_LOG" ] || fail "second run called gh: $(cat "$FAKE_GH_LOG")"
  [ "$(git -C "$WORK" rev-parse --abbrev-ref HEAD)" = main ] || fail "second run left main"
  [ -z "$(git -C "$WORK" status --porcelain)" ] || fail "second run left changes: $(git -C "$WORK" status --porcelain)"
}

@test "release-repin.yml runs on pushes to main touching a re-pinned input, never on workflow_run" {
  [ -f "$REPO_ROOT/$WORKFLOW" ] || fail "$WORKFLOW does not exist"
  on="$(yq -o=json -I=0 '.on' "$REPO_ROOT/$WORKFLOW")" || fail "$WORKFLOW is not valid YAML"
  jq -e 'type == "object"' <<<"$on" >/dev/null || fail "$WORKFLOW .on is not a mapping: $on"
  jq -e 'has("workflow_run") | not' <<<"$on" >/dev/null || fail "$WORKFLOW triggers on workflow_run"
  jq -e 'has("pull_request_target") | not' <<<"$on" >/dev/null || fail "$WORKFLOW triggers on pull_request_target"
  jq -e '.push.branches == ["main"]' <<<"$on" >/dev/null ||
    fail "$WORKFLOW push trigger is not limited to main: $(jq -c .push <<<"$on")"
  for path in images/catalog.yaml "${APP_DOCKERFILES[@]}" 'tests/fixtures/images/**' "$SCRIPT"; do
    jq -e --arg p "$path" '.push.paths | index($p) != null' <<<"$on" >/dev/null ||
      fail "$WORKFLOW push paths do not include $path: $(jq -c .push.paths <<<"$on")"
  done
  for job in dockerfiles workloads fixtures; do
    JOB="$job" yq -e '.jobs[strenv(JOB)].steps[] | select((.run // "") | test("release-repin.sh " + strenv(JOB)))' \
      "$REPO_ROOT/$WORKFLOW" >/dev/null 2>&1 || fail "job $job does not run $SCRIPT $job"
  done
}

@test "release-repin.yml jobs hold minimal permissions, pin actions by SHA and never push to main" {
  [ "$(yq -o=json -I=0 '.permissions' "$REPO_ROOT/$WORKFLOW")" = "{}" ] ||
    fail "$WORKFLOW top-level permissions are not {}: $(yq -o=json -I=0 '.permissions' "$REPO_ROOT/$WORKFLOW")"
  permissions="$(yq -o=json -I=0 '.jobs | with_entries(.value = .value.permissions)' "$REPO_ROOT/$WORKFLOW")"
  expected='{"dockerfiles":{"contents":"write","pull-requests":"write"},
    "workloads":{"contents":"write","pull-requests":"write","packages":"read"},
    "fixtures":{"contents":"write","pull-requests":"write","packages":"read"}}'
  jq -e --argjson want "$expected" '. == $want' <<<"$permissions" >/dev/null ||
    fail "$WORKFLOW job permissions are $permissions, expected $(jq -c . <<<"$expected")"

  uses="$(yq '[.jobs[].uses, .jobs[].steps[]?.uses] | .[] | select(. != null)' "$REPO_ROOT/$WORKFLOW")"
  [ -n "$uses" ] || fail "$WORKFLOW uses no action"
  unpinned="$(grep -vE '^[^@[:space:]]+@[0-9a-f]{40}$' <<<"$uses" || true)"
  [ -z "$unpinned" ] || fail "actions not pinned by commit SHA: $(paste -sd ' ' - <<<"$unpinned")"

  pushes="$(yq '.jobs[].steps[] | select((.run // "") | test("git[[:space:]]+push")) | .run' "$REPO_ROOT/$WORKFLOW")"
  [ -z "$pushes" ] || fail "$WORKFLOW pushes from a step instead of the script's pull request: $pushes"
}

@test "dockerfiles re-pins every app FROM to the supported catalog digest, then does nothing" {
  make_scratch_repo
  yq -i "(.images[] | select(.name == \"python\" and .status == \"supported\") | .digest) = \"$NEW_PYTHON\"" \
    "$WORK/images/catalog.yaml"
  yq -i "(.images[] | select(.name == \"java\" and .status == \"supported\") | .digest) = \"$NEW_JAVA\"" \
    "$WORK/images/catalog.yaml"
  git_quiet -C "$WORK" commit -am "catalog moved on main"
  git_quiet -C "$WORK" push origin main
  main_before="$(origin_main)"

  run_repin 4242 dockerfiles
  [ "$status" -eq 0 ] || fail "dockerfiles failed (exit $status): $output"
  assert_repin_pr release-repin-dockerfiles-4242 "$main_before" "${APP_DOCKERFILES[@]}"
  for case in "apps/dt-bridge/Dockerfile|python|$NEW_PYTHON|2" "apps/runtime-demo/Dockerfile|python|$NEW_PYTHON|1" \
    "apps/hello-java/Dockerfile|java|$NEW_JAVA|2"; do
    IFS='|' read -r file golden digest stages <<<"$case"
    froms="$(git -C "$ORIGIN" show "release-repin-dockerfiles-4242:$file" | grep -E '^FROM ')"
    [ "$(grep -cF "FROM $GHCR/golden/$golden@$digest" <<<"$froms")" -eq "$stages" ] ||
      fail "$file FROM lines are not all on golden/$golden@$digest:"$'\n'"$froms"
    [ "$(wc -l <<<"$froms")" -eq "$stages" ] || fail "$file FROM lines changed in number:"$'\n'"$froms"
  done

  merge_repin_pr release-repin-dockerfiles-4242
  main_after="$(origin_main)"
  branches="$(origin_branches)"
  run_repin 4243 dockerfiles
  assert_noop "$main_after" "$branches"
}

@test "workloads re-pins each workload to the image published for the commit, then does nothing" {
  make_scratch_repo
  printf '%s %s\n' \
    "$GHCR/apps/hello-java:sha-$MAIN_SHA" "$NEW_HELLO_JAVA" \
    "$GHCR/apps/dt-bridge:sha-$MAIN_SHA" "$NEW_DT_BRIDGE" \
    "$GHCR/apps/runtime-demo:sha-$MAIN_SHA" "$NEW_RUNTIME_DEMO" \
    "$GHCR/apps/hello-java:sha-ffffffffffffffffffffffffffffffffffffffff" "$NEW_DT_BRIDGE" >"$FAKE_REGISTRY"
  main_before="$(origin_main)"

  run_repin 4242 workloads "$MAIN_SHA"
  [ "$status" -eq 0 ] || fail "workloads failed (exit $status): $output"
  assert_repin_pr release-repin-workloads-4242 "$main_before" "${WORKLOADS[@]}"
  for case in "hello-java|$NEW_HELLO_JAVA" "dt-bridge|$NEW_DT_BRIDGE" "runtime-demo|$NEW_RUNTIME_DEMO"; do
    IFS='|' read -r app digest <<<"$case"
    file="platform/workloads/$app/$app.yaml"
    images="$(git -C "$ORIGIN" show "release-repin-workloads-4242:$file" | grep -oE "harbor\.127\.0\.0\.1\.nip\.io/apps/$app@sha256:[0-9a-f]{64}" | sort -u)"
    [ "$images" = "harbor.127.0.0.1.nip.io/apps/$app@$digest" ] ||
      fail "$file references '$(paste -sd ' ' - <<<"$images")', expected harbor.127.0.0.1.nip.io/apps/$app@$digest"
  done

  merge_repin_pr release-repin-workloads-4242
  main_after="$(origin_main)"
  branches="$(origin_branches)"
  run_repin 4243 workloads "$MAIN_SHA"
  assert_noop "$main_after" "$branches"
}

@test "fixtures re-pins the demo fixtures commit once its fixtures are published, then does nothing" {
  make_scratch_repo
  old_commit="$(yq '.commit' "$WORK/$DEMO_FIXTURES")"
  [ "$old_commit" != "$MAIN_SHA" ] || fail "control: $DEMO_FIXTURES already pins $MAIN_SHA"
  main_before="$(origin_main)"

  # Not published yet: the budget is spent, nothing changes.
  run_repin 4241 fixtures "$MAIN_SHA"
  [ "$status" -eq 0 ] || fail "fixtures failed on an unpublished commit (exit $status): $output"
  [ "$(origin_branches)" = main ] || fail "fixtures pushed a branch for unpublished fixtures: $(origin_branches)"
  [ ! -s "$FAKE_GH_LOG" ] || fail "fixtures called gh for unpublished fixtures: $(cat "$FAKE_GH_LOG")"

  printf '%s %s\n' "$GHCR/fixtures/compliant:sha-$MAIN_SHA" "$NEW_FIXTURE" >"$FAKE_REGISTRY"
  run_repin 4242 fixtures "$MAIN_SHA"
  [ "$status" -eq 0 ] || fail "fixtures failed (exit $status): $output"
  assert_repin_pr release-repin-fixtures-4242 "$main_before" "$DEMO_FIXTURES"
  pinned="$(git -C "$ORIGIN" show "release-repin-fixtures-4242:$DEMO_FIXTURES" | yq '.commit')"
  [ "$pinned" = "$MAIN_SHA" ] || fail "$DEMO_FIXTURES pins '$pinned', expected $MAIN_SHA"

  merge_repin_pr release-repin-fixtures-4242
  main_after="$(origin_main)"
  branches="$(origin_branches)"
  run_repin 4243 fixtures "$MAIN_SHA"
  assert_noop "$main_after" "$branches"
}

@test "release-repin.yml wait jobs outlast the script's worst-case wait for images never published" {
  make_scratch_repo
  budget=3
  default_timeout="$(grep -oE 'RELEASE_REPIN_TIMEOUT:-[0-9]+' "$REPO_ROOT/$SCRIPT" | head -n1 | grep -oE '[0-9]+$')"
  [ -n "$default_timeout" ] || fail "$SCRIPT has no RELEASE_REPIN_TIMEOUT default"
  problems=()
  for job in workloads fixtures; do
    # Nothing published: the script spends its whole wait. Sequential per-image waits take refs x budget.
    started=$SECONDS
    run env PATH="$FAKE_PATH:$PATH" FAKE_REGISTRY="$FAKE_REGISTRY" FAKE_GH_LOG="$FAKE_GH_LOG" GITHUB_RUN_ID=4242 \
      RELEASE_REPIN_TIMEOUT="$budget" RELEASE_REPIN_INTERVAL=1 "$WORK/$SCRIPT" "$job" "$MAIN_SHA"
    elapsed=$((SECONDS - started))
    [ "$status" -eq 0 ] || fail "$job failed on unpublished images (exit $status): $output"
    refs="$(grep -c 'not published within' <<<"$output" || true)"
    [ "$refs" -ge 1 ] || fail "$job reported no unpublished image: $output"
    if [ "$elapsed" -ge $((2 * budget)) ]; then
      worst=$((refs * default_timeout))
    else
      worst="$default_timeout"
    fi

    timeout_env="$(JOB="$job" yq -r '[.jobs[strenv(JOB)].steps[] | select((.run // "") | test("release-repin.sh " + strenv(JOB))) | .env.RELEASE_REPIN_TIMEOUT][0]
      // .jobs[strenv(JOB)].env.RELEASE_REPIN_TIMEOUT // .env.RELEASE_REPIN_TIMEOUT // ""' "$REPO_ROOT/$WORKFLOW")"
    [ -z "$timeout_env" ] || worst=$((worst * timeout_env / default_timeout))
    minutes="$(JOB="$job" yq -r ".jobs[strenv(JOB)][\"timeout-minutes\"] // $DEFAULT_JOB_TIMEOUT_MINUTES" "$REPO_ROOT/$WORKFLOW")"
    [ $((minutes * 60)) -ge $((worst + JOB_SETUP_SECONDS)) ] ||
      problems+=("job $job has timeout-minutes: $minutes ($((minutes * 60))s) but the script waits up to ${worst}s for $refs image(s) (${elapsed}s for $refs x ${budget}s here) plus ${JOB_SETUP_SECONDS}s of setup: the job is killed before it opens its pull request")
  done
  [ "${#problems[@]}" -eq 0 ] || fail "$(printf '%s\n' "${problems[@]}")"
}

@test "task release:repin re-pins every step to the original HEAD after the dockerfiles step commits" {
  make_scratch_repo
  for path in Taskfile.yml "${E2E_FILES[@]}"; do
    mkdir -p "$WORK/$(dirname "$path")"
    cp "$REPO_ROOT/$path" "$WORK/$path"
  done
  yq -i "(.images[] | select(.name == \"python\" and .status == \"supported\") | .digest) = \"$NEW_PYTHON\"" \
    "$WORK/images/catalog.yaml"
  yq -i "(.images[] | select(.name == \"java\" and .status == \"supported\") | .digest) = \"$NEW_JAVA\"" \
    "$WORK/images/catalog.yaml"
  git_quiet -C "$WORK" add -A
  git_quiet -C "$WORK" commit -m "catalog moved on main" || fail "cannot commit the catalog move"
  git_quiet -C "$WORK" push origin main || fail "cannot push the catalog move"
  head="$(git -C "$WORK" rev-parse HEAD)"
  main_before="$(origin_main)"
  # main at $head built every app and the fixtures: the images a correct run re-pins to.
  printf '%s %s\n' \
    "$GHCR/apps/hello-java:sha-$head" "$NEW_HELLO_JAVA" \
    "$GHCR/apps/dt-bridge:sha-$head" "$NEW_DT_BRIDGE" \
    "$GHCR/apps/runtime-demo:sha-$head" "$NEW_RUNTIME_DEMO" \
    "$GHCR/fixtures/compliant:sha-$head" "$NEW_FIXTURE" >"$FAKE_REGISTRY"

  run bash -c 'cd "$1" && exec env PATH="$2:$PATH" FAKE_REGISTRY="$3" FAKE_GH_LOG="$4" GITHUB_RUN_ID=4242 \
    RELEASE_REPIN_INTERVAL=1 task release:repin 2>&1' _ "$WORK" "$FAKE_PATH" "$FAKE_REGISTRY" "$FAKE_GH_LOG"
  [ "$(origin_main)" = "$main_before" ] || fail "task release:repin moved origin main"
  git -C "$ORIGIN" rev-parse --verify --quiet refs/heads/release-repin-dockerfiles-4242 >/dev/null ||
    fail "control: the dockerfiles step opened no pull request (exit $status): $output"
  repin_commit="$(git -C "$ORIGIN" rev-parse refs/heads/release-repin-dockerfiles-4242)"

  if [ "$status" -ne 0 ]; then
    # Failing loudly is acceptable: an ERROR naming the commit the later step would have used.
    errors="$(grep -E '^ERROR: ' <<<"$output" || true)"
    grep -qE "${head:0:7}|${repin_commit:0:7}" <<<"$errors" ||
      fail "task release:repin exited $status without an ERROR naming the original HEAD ${head:0:12} or the re-pin commit ${repin_commit:0:12}: $output"
    for step in workloads fixtures; do
      ! git -C "$ORIGIN" rev-parse --verify --quiet "refs/heads/release-repin-$step-4242" >/dev/null ||
        fail "task release:repin failed but still pushed release-repin-$step-4242"
    done
    return 0
  fi

  problems=()
  skipped="$(grep -E 'not published within|already pin' <<<"$output" || true)"
  [ -z "$skipped" ] || problems+=("a later step skipped after the dockerfiles commit ${repin_commit:0:12} moved HEAD off ${head:0:12}: $(paste -sd ' ' - <<<"$skipped")")
  for case in "workloads|${WORKLOADS[*]}" "fixtures|$DEMO_FIXTURES" "e2e-params|${E2E_FILES[*]}"; do
    IFS='|' read -r step files <<<"$case"
    branch="release-repin-$step-4242"
    if ! git -C "$ORIGIN" rev-parse --verify --quiet "refs/heads/$branch" >/dev/null; then
      problems+=("the $step step opened no pull request ($branch not pushed)")
      continue
    fi
    changed="$(git -C "$ORIGIN" diff --name-only main "$branch" | sort | paste -sd ' ' -)"
    expected="$(tr ' ' '\n' <<<"$files" | sort | paste -sd ' ' -)"
    [ "$changed" = "$expected" ] || problems+=("$branch changes '$changed' against main, expected only '$expected'")
  done
  for case in "hello-java|$NEW_HELLO_JAVA" "dt-bridge|$NEW_DT_BRIDGE" "runtime-demo|$NEW_RUNTIME_DEMO"; do
    IFS='|' read -r app digest <<<"$case"
    file="platform/workloads/$app/$app.yaml"
    images="$(git -C "$ORIGIN" show "release-repin-workloads-4242:$file" 2>/dev/null |
      grep -oE "harbor\.127\.0\.0\.1\.nip\.io/apps/$app@sha256:[0-9a-f]{64}" | sort -u)"
    [ "$images" = "harbor.127.0.0.1.nip.io/apps/$app@$digest" ] ||
      problems+=("$file is not re-pinned to the image built at ${head:0:12} (apps/$app@$digest): '$(paste -sd ' ' - <<<"$images")'")
  done
  pinned="$(git -C "$ORIGIN" show "release-repin-fixtures-4242:$DEMO_FIXTURES" 2>/dev/null | yq '.commit')"
  [ "$pinned" = "$head" ] || problems+=("$DEMO_FIXTURES pins '$pinned', expected the original HEAD $head")
  [ "${#problems[@]}" -eq 0 ] || fail "$(printf '%s\n' "${problems[@]}")"
}
