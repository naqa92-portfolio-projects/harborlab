#!/usr/bin/env bats
# `task lint -- <dir>` (the platform CI lint) on fixture repositories built in $BATS_TEST_TMPDIR:
# a clean baseline passes, and one deliberate defect per check fails with that check named.
# Bad fixtures are never committed, so the repository's own scanners stay clean.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
PLATFORM_CI=.github/workflows/platform-ci.yml
GOLDEN_REPO=ghcr.io/naqa92-portfolio-projects/harborlab/golden
SUPPORTED_DIGEST=sha256:1111111111111111111111111111111111111111111111111111111111111111
EOL_DIGEST=sha256:3333333333333333333333333333333333333333333333333333333333333333
CHECKOUT_PINNED='actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'

fail() {
  echo "$*" >&2
  return 1
}

commit_fixture() {
  git -C "$1" add -A
  git -C "$1" commit -qm "$2"
}

write_dockerfile() {
  cat >"$1/apps/hello/Dockerfile" <<EOF
FROM $2
WORKDIR ${3:-/app}
COPY app.py /app/app.py
USER 65532:65532
CMD ["python", "/app/app.py"]
EOF
}

# A git repository that passes every check: a catalog, an app Dockerfile FROM a supported golden
# image, and a hardened, SHA-pinned workflow.
make_clean_fixture() {
  local dir="$1"
  mkdir -p "$dir/images" "$dir/apps/hello" "$dir/.github/workflows"
  git init -q "$dir"
  git -C "$dir" config user.email tests@example.invalid
  git -C "$dir" config user.name tests

  cat >"$dir/images/catalog.yaml" <<EOF
images:
  - name: python
    version: "3.13"
    digest: $SUPPORTED_DIGEST
    status: supported
    released: "2026-09-01"
    eol: "2029-10-31"
  - name: python
    version: "3.9"
    digest: $EOL_DIGEST
    status: eol
    released: "2024-01-10"
    eol: "2025-10-31"
EOF
  write_dockerfile "$dir" "$GOLDEN_REPO/python:3.13@$SUPPORTED_DIGEST"
  printf 'print("hello")\n' >"$dir/apps/hello/app.py"
  cat >"$dir/.github/workflows/ci.yml" <<EOF
name: ci
on:
  pull_request:
permissions: {}
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: $CHECKOUT_PINNED
        with:
          persist-credentials: false
      - run: echo ok
EOF
  commit_fixture "$dir" "clean baseline"
}

# Runs the platform lint on directory $1 from the repository root; sets status and output.
run_lint() {
  run bash -c 'cd "$1" && exec task lint -- "$2"' _ "$REPO_ROOT" "$1"
}

assert_lint_fails_with() {
  local check="$1" defect="$2"
  [ "$status" -ne 0 ] || fail "task lint exits 0 on $defect"
  grep -qE "FAILED $check([[:space:]]|\$)" <<<"$output" ||
    fail "task lint does not report 'FAILED $check' on $defect:"$'\n'"$(tail -n 30 <<<"$output")"
}

@test "platform lint passes on a clean fixture" {
  fixture="$BATS_TEST_TMPDIR/fixture"
  make_clean_fixture "$fixture"
  run_lint "$fixture"
  [ "$status" -eq 0 ] || fail "task lint fails on the clean fixture (exit $status):"$'\n'"$(tail -n 30 <<<"$output")"
  ! grep -q 'FAILED ' <<<"$output" || fail "task lint reports a failed check on the clean fixture: $output"
}

@test "zizmor finding fails the lint" {
  fixture="$BATS_TEST_TMPDIR/fixture"
  make_clean_fixture "$fixture"
  cat >"$fixture/.github/workflows/pr-title.yml" <<'EOF'
name: pr-title
on:
  pull_request:
permissions: {}
jobs:
  title:
    runs-on: ubuntu-24.04
    steps:
      - name: Print the pull request title
        run: echo "${{ github.event.pull_request.title }}"
EOF
  commit_fixture "$fixture" "template injection"
  run_lint "$fixture"
  assert_lint_fails_with zizmor "a template injection in a run step"
}

@test "action not pinned by SHA fails the lint" {
  fixture="$BATS_TEST_TMPDIR/fixture"
  make_clean_fixture "$fixture"
  sed -i "s|$CHECKOUT_PINNED|actions/checkout@v7.0.1|" "$fixture/.github/workflows/ci.yml"
  grep -q 'actions/checkout@v7.0.1$' "$fixture/.github/workflows/ci.yml" || fail "fixture: the tag pin was not written"
  commit_fixture "$fixture" "tag-pinned action"
  run_lint "$fixture"
  assert_lint_fails_with pinned-actions "actions/checkout pinned by tag"
}

@test "detected secret fails the lint" {
  fixture="$BATS_TEST_TMPDIR/fixture"
  make_clean_fixture "$fixture"
  mkdir -p "$fixture/config"
  # Split so that no scanner finds a token in this file; the fixture exists only at run time.
  printf 'GITHUB_TOKEN=%s\n' "ghp_""8fK2mQ9xLr4TzW7vNc1bY6hJ3dS5gPa0eUoI" >"$fixture/config/app.env"
  commit_fixture "$fixture" "leaked token"
  run_lint "$fixture"
  assert_lint_fails_with gitleaks "a committed GitHub token"
}

@test "hadolint error fails the lint" {
  fixture="$BATS_TEST_TMPDIR/fixture"
  make_clean_fixture "$fixture"
  # DL3000 (error): WORKDIR must be absolute.
  write_dockerfile "$fixture" "$GOLDEN_REPO/python:3.13@$SUPPORTED_DIGEST" app
  commit_fixture "$fixture" "relative WORKDIR"
  run_lint "$fixture"
  assert_lint_fails_with hadolint "a relative WORKDIR (DL3000)"
}

@test "Trivy HIGH misconfiguration fails the lint" {
  fixture="$BATS_TEST_TMPDIR/fixture"
  make_clean_fixture "$fixture"
  mkdir -p "$fixture/deploy"
  cat >"$fixture/deploy/privileged-pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privileged
spec:
  containers:
    - name: app
      image: $GOLDEN_REPO/python:3.13@$SUPPORTED_DIGEST
      securityContext:
        privileged: true
EOF
  commit_fixture "$fixture" "privileged pod"
  run_lint "$fixture"
  assert_lint_fails_with trivy-config "a privileged container manifest (HIGH)"
}

@test "kube-linter error fails the lint" {
  fixture="$BATS_TEST_TMPDIR/fixture"
  make_clean_fixture "$fixture"
  mkdir -p "$fixture/deploy"
  cat >"$fixture/deploy/deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello
spec:
  replicas: 1
  selector:
    matchLabels:
      app: hello
  template:
    metadata:
      labels:
        app: goodbye
    spec:
      containers:
        - name: app
          image: $GOLDEN_REPO/python:3.13@$SUPPORTED_DIGEST
EOF
  commit_fixture "$fixture" "selector matches no pod"
  run_lint "$fixture"
  assert_lint_fails_with kube-linter "a Deployment whose selector matches none of its pods"
}

@test "FROM outside supported golden images fails the lint" {
  fixture="$BATS_TEST_TMPDIR/non-catalog"
  make_clean_fixture "$fixture"
  write_dockerfile "$fixture" "docker.io/library/python:3.13-slim"
  commit_fixture "$fixture" "FROM a non-catalog image"
  run_lint "$fixture"
  assert_lint_fails_with from-golden "a Dockerfile FROM docker.io/library/python"

  fixture="$BATS_TEST_TMPDIR/eol"
  make_clean_fixture "$fixture"
  write_dockerfile "$fixture" "$GOLDEN_REPO/python:3.9@$EOL_DIGEST"
  commit_fixture "$fixture" "FROM an eol golden image"
  run_lint "$fixture"
  assert_lint_fails_with from-golden "a Dockerfile FROM a golden image marked eol in the catalog"
}

@test "heredoc line spoofing a golden FROM fails the lint" {
  fixture="$BATS_TEST_TMPDIR/heredoc-from"
  make_clean_fixture "$fixture"
  # The real base is Docker Hub python; the last line starting with FROM is heredoc content naming the
  # supported golden image, which a line-oriented reader takes for the final FROM.
  cat >"$fixture/apps/hello/Dockerfile" <<EOF
FROM docker.io/library/python:3.13-slim
COPY <<SPOOF /app/notes.txt
FROM $GOLDEN_REPO/python:3.13@$SUPPORTED_DIGEST
SPOOF
COPY app.py /app/app.py
USER 65532:65532
CMD ["python", "/app/app.py"]
EOF
  commit_fixture "$fixture" "heredoc FROM spoof"
  run_lint "$fixture"
  assert_lint_fails_with from-golden "a Dockerfile on Docker Hub python whose heredoc carries a golden FROM line"
}

@test "syntax directive naming a custom frontend fails the lint" {
  fixture="$BATS_TEST_TMPDIR/syntax-frontend"
  make_clean_fixture "$fixture"
  # A custom BuildKit frontend decides the base itself, whatever the FROM lines say.
  sed -i "1i # syntax=ghcr.io/attacker-example/dockerfile-frontend:1" "$fixture/apps/hello/Dockerfile"
  head -n 1 "$fixture/apps/hello/Dockerfile" | grep -q '^# syntax=ghcr.io/attacker-example/' ||
    fail "fixture: the syntax directive was not written"
  commit_fixture "$fixture" "custom frontend"
  run_lint "$fixture"
  assert_lint_fails_with from-golden "a Dockerfile whose # syntax= directive names a custom frontend"
}

@test "platform lint passes on the repository" {
  run bash -c 'cd "$1" && exec task lint' _ "$REPO_ROOT"
  [ "$status" -eq 0 ] || fail "task lint fails on the repository (exit $status):"$'\n'"$(tail -n 40 <<<"$output")"
  ! grep -q 'FAILED ' <<<"$output" || fail "task lint reports a failed check on the repository: $output"
}

@test "platform CI runs the lint on pull requests" {
  [ -f "$REPO_ROOT/$PLATFORM_CI" ] || fail "$PLATFORM_CI does not exist"
  on="$(yq -o=json '.on' "$REPO_ROOT/$PLATFORM_CI")" || fail "$PLATFORM_CI is not valid YAML"
  jq -e 'if type == "object" then has("pull_request")
      elif type == "array" then index("pull_request") != null
      else . == "pull_request" end' <<<"$on" >/dev/null || fail "$PLATFORM_CI does not trigger on pull_request"
  jq -e 'type != "object" or ((.pull_request // {}) | (has("paths") or has("paths-ignore") or has("branches")) | not)' \
    <<<"$on" >/dev/null || fail "$PLATFORM_CI filters pull_request by paths or branches: $(jq -c .pull_request <<<"$on")"

  # The lint runs in a job CI does not allow to fail, from a step it does not allow to fail, on a
  # full-history checkout (gitleaks scans every commit of the PR).
  yq -o=json -I=0 '.jobs[]' "$REPO_ROOT/$PLATFORM_CI" | jq -e -s '
    any(.[]; (.["continue-on-error"] != true)
      and any(.steps[]?; (.["continue-on-error"] != true)
        and ((.run // "") | test("(^|[^A-Za-z0-9:_-])task[ \t]+lint([ \t]|$)")))
      and any(.steps[]?; ((.uses // "") | startswith("actions/checkout@"))
        and (((.with // {})["fetch-depth"] // "") | tostring) == "0"))' >/dev/null ||
    fail "no blocking job of $PLATFORM_CI runs 'task lint' after a fetch-depth: 0 checkout"
}
