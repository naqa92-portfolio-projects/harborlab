#!/usr/bin/env bats
# images/catalog.yaml: schema validation, generated Kyverno params ConfigMap and doc, drift check
# and its wiring in the platform CI.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
FIXTURES="$(cd "$BATS_TEST_DIRNAME/../fixtures/catalog" && pwd)"
CATALOG=images/catalog.yaml
PARAMS_CONFIGMAP=policies/params/golden-images.yaml
CATALOG_DOC=docs/golden-images.md
PLATFORM_CI=.github/workflows/platform-ci.yml
GOLDEN_IMAGES=(python java)

fail() {
  echo "$*" >&2
  return 1
}

# Runs a Taskfile task from directory $1; sets status and output (stdout + stderr).
run_task_in() {
  run bash -c 'cd "$1" && shift && exec task "$@"' _ "$@"
}

# Copies the working tree (tracked and untracked, git-ignored files excluded) to $1.
copy_repo() {
  mkdir -p "$1"
  (cd "$REPO_ROOT" && git ls-files -z --cached --others --exclude-standard |
    while IFS= read -r -d '' path; do [ -e "$path" ] && printf '%s\0' "$path"; done |
    tar --null -T - -cf -) | tar -C "$1" -xf -
}

configmap_key() {
  echo "sha256.${1#sha256:}"
}

# `run` scripts of the steps CI does not allow to fail, one job per JSON line.
blocking_jobs() {
  yq -o=json -I=0 '.jobs[] | select(.["continue-on-error"] != true)
    | .steps = [.steps[]? | select(.["continue-on-error"] != true)]' "$REPO_ROOT/$PLATFORM_CI"
}

assert_runs_on_every_pull_request() {
  local on
  on="$(yq -o=json '.on' "$REPO_ROOT/$PLATFORM_CI")" || fail "$PLATFORM_CI is not valid YAML"
  jq -e 'if type == "object" then has("pull_request")
      elif type == "array" then index("pull_request") != null
      else . == "pull_request" end' <<<"$on" >/dev/null || fail "$PLATFORM_CI does not trigger on pull_request"
  jq -e 'type != "object" or ((.pull_request // {}) | (has("paths") or has("paths-ignore") or has("branches")) | not)' \
    <<<"$on" >/dev/null || fail "$PLATFORM_CI filters pull_request by paths or branches: $(jq -c .pull_request <<<"$on")"
}

@test "catalog validation rejects invalid entries" {
  run_task_in "$REPO_ROOT" catalog:validate -- "$FIXTURES/valid.yaml"
  [ "$status" -eq 0 ] || fail "control: catalog:validate rejects the valid fixture (exit $status): $output"

  # "<fixture>|<field the error names>"
  for case in "missing-digest|digest" "invalid-status|status" "malformed-digest|digest" "invalid-date|eol"; do
    IFS='|' read -r fixture field <<<"$case"
    run_task_in "$REPO_ROOT" catalog:validate -- "$FIXTURES/$fixture.yaml"
    [ "$status" -ne 0 ] || fail "catalog:validate accepts $fixture.yaml"
    [[ "$output" == *"$field"* ]] || fail "catalog:validate rejects $fixture.yaml without naming '$field': $output"
  done
}

@test "generated ConfigMap and doc match the catalog" {
  run_task_in "$REPO_ROOT" catalog:validate
  [ "$status" -eq 0 ] || fail "$CATALOG is invalid (exit $status): $output"
  for name in "${GOLDEN_IMAGES[@]}"; do
    yq -e ".images[] | select(.name == \"$name\" and .status == \"supported\")" "$REPO_ROOT/$CATALOG" >/dev/null ||
      fail "$CATALOG has no supported $name entry"
  done

  copy="$BATS_TEST_TMPDIR/repo"
  copy_repo "$copy"
  run_task_in "$copy" catalog:generate
  [ "$status" -eq 0 ] || fail "catalog:generate failed (exit $status): $output"
  for file in "$PARAMS_CONFIGMAP" "$CATALOG_DOC"; do
    [ -f "$REPO_ROOT/$file" ] || fail "$file is not in the repository"
    run diff -u "$REPO_ROOT/$file" "$copy/$file"
    [ "$status" -eq 0 ] || fail "committed $file differs from a fresh catalog:generate:"$'\n'"$(head -n 40 <<<"$output")"
  done

  configmap="$REPO_ROOT/$PARAMS_CONFIGMAP"
  [ "$(yq '.kind + " " + .metadata.namespace + "/" + .metadata.name' "$configmap")" = "ConfigMap kyverno/golden-images" ] ||
    fail "$PARAMS_CONFIGMAP is not the ConfigMap kyverno/golden-images"
  while IFS=$'\t' read -r name version digest status; do
    value="$(yq ".data[\"$(configmap_key "$digest")\"] // \"\"" "$configmap")"
    [ "$value" = "$status" ] ||
      fail "$PARAMS_CONFIGMAP data[$(configmap_key "$digest")] is '$value', expected '$status' ($name $version)"
    grep -F "${digest#sha256:}" "$REPO_ROOT/$CATALOG_DOC" | grep -F "$name" | grep -F "$version" | grep -qF "$status" ||
      fail "$CATALOG_DOC has no row with $name, $version, $digest and $status"
  done < <(yq -r '.images[] | [.name, .version, .digest, .status] | @tsv' "$REPO_ROOT/$CATALOG")
}

@test "drift check fails when generated files are out of date" {
  copy="$BATS_TEST_TMPDIR/repo"
  copy_repo "$copy"
  run_task_in "$copy" catalog:check
  [ "$status" -eq 0 ] || fail "control: catalog:check fails on an up-to-date copy (exit $status): $output"

  digest="$(yq '.images[0].digest' "$copy/$CATALOG")"
  old_status="$(yq '.images[0].status' "$copy/$CATALOG")"
  new_status=deprecated
  [ "$old_status" != deprecated ] || new_status=supported
  yq -i ".images[0].status = \"$new_status\"" "$copy/$CATALOG"

  run_task_in "$copy" catalog:check
  [ "$status" -ne 0 ] || fail "catalog:check passes although $CATALOG changed ($old_status -> $new_status) without regenerating"
  run diff -q "$REPO_ROOT/$PARAMS_CONFIGMAP" "$copy/$PARAMS_CONFIGMAP"
  [ "$status" -eq 0 ] || fail "catalog:check rewrote $PARAMS_CONFIGMAP instead of only reporting the drift"

  run_task_in "$copy" catalog:generate
  [ "$status" -eq 0 ] || fail "catalog:generate failed (exit $status): $output"
  run_task_in "$copy" catalog:check
  [ "$status" -eq 0 ] || fail "catalog:check still fails after catalog:generate: $output"
  [ "$(yq ".data[\"$(configmap_key "$digest")\"]" "$copy/$PARAMS_CONFIGMAP")" = "$new_status" ] ||
    fail "regenerated $PARAMS_CONFIGMAP does not carry the new status $new_status of $digest"
}

@test "platform CI runs the catalog drift check on pull requests" {
  [ -f "$REPO_ROOT/$PLATFORM_CI" ] || fail "$PLATFORM_CI does not exist"
  assert_runs_on_every_pull_request
  blocking_jobs | jq -e -s 'any(.[]; any(.steps[]; (.run // "") | test("(^|[^A-Za-z0-9:_-])task[ \t]+catalog:check([ \t]|$)")))' \
    >/dev/null || fail "no blocking step of $PLATFORM_CI runs 'task catalog:check'"
}
