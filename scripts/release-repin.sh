#!/usr/bin/env bash
# Post-merge re-pin (R10): after a merge to main, only build-image.yml@refs/heads/main is trusted (T2),
# so every pin still carrying a prd-* build must be brought forward once main has rebuilt it. Idempotent:
# each command opens a pull request only when something actually changed, and never pushes to main
# directly. release-repin.yml runs the four commands, in this order, on the pushes that can need them;
# `task release:repin` runs them for the current HEAD instead, for a manual run after a merge.
#
#   dockerfiles          re-pin the app Dockerfile FROM lines to the `supported` digests of
#                        images/catalog.yaml (golden.yml's own catalog job keeps that file in step)
#   workloads [sha]      wait for apps/<name>:sha-<sha> (build-image.yml, triggered by the Dockerfile
#                        re-pin above) and re-pin platform/workloads/<name>/<name>.yaml to it
#   fixtures [sha]       wait for fixtures/compliant:sha-<sha> (fixtures.yml) and re-pin
#                        images/demo-fixtures.yaml's commit to it
#   e2e-params           re-pin the E2E fixture Dockerfiles and the Kyverno E2E params (R11) to the
#                        `supported` digests of images/catalog.yaml, leaving their fixture-only
#                        deprecated/eol entries (absent from the catalog) untouched
#
# sha defaults to the current HEAD. workloads/fixtures wait up to RELEASE_REPIN_TIMEOUT seconds in total
# (default 900, one deadline shared by every image of the command), polling every RELEASE_REPIN_INTERVAL
# seconds (default 20): the build that publishes them runs concurrently, triggered by the same push.
# Each pull request branches from the checked-out commit and the checkout returns to it afterwards, so
# the steps of one run never stack on each other's commits.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY="ghcr.io/naqa92-portfolio-projects/harborlab"
CATALOG="$REPO_ROOT/images/catalog.yaml"
DEMO_FIXTURES="$REPO_ROOT/images/demo-fixtures.yaml"
TIMEOUT="${RELEASE_REPIN_TIMEOUT:-900}"
INTERVAL="${RELEASE_REPIN_INTERVAL:-20}"
START_SECONDS=$SECONDS
# app -> Dockerfile path, and the golden image it is built on
declare -A APP_DOCKERFILE=(
  [hello-java]=apps/hello-java/Dockerfile
  [dt-bridge]=apps/dt-bridge/Dockerfile
  [runtime-demo]=apps/runtime-demo/Dockerfile
)
declare -A APP_GOLDEN=(
  [hello-java]=java
  [dt-bridge]=python
  [runtime-demo]=python
)
# E2E fixture Dockerfiles built on the supported golden python digest, and the files holding a
# fixture-only copy of the golden-images Kyverno params (in images/catalog.yaml order: python, java).
FIXTURE_DOCKERFILES=(
  tests/fixtures/images/compliant/Dockerfile
  tests/fixtures/images/missing-labels/Dockerfile
)
E2E_GOLDEN_FILES=(
  tests/chainsaw/params/golden-images.yaml
  tests/kyverno/workload/context.yaml
)
declare -A APP_WORKLOAD=(
  [hello-java]=platform/workloads/hello-java/hello-java.yaml
  [dt-bridge]=platform/workloads/dt-bridge/dt-bridge.yaml
  [runtime-demo]=platform/workloads/runtime-demo/runtime-demo.yaml
)

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# Prints the digest of ref $1, waiting for it to be published until $TIMEOUT seconds have elapsed since the
# script started (one deadline for all refs); prints nothing (not an error) once it is spent, since the sibling build may simply not have been triggered by this
# push. Dies on any lookup error other than "not found yet".
wait_for_digest() {
  local ref="$1" out
  while true; do
    if out="$(crane digest "$ref" 2>&1)"; then
      [[ "$out" =~ (sha256:[0-9a-f]{64}) ]] || die "unexpected crane output for $ref: $out"
      echo "${BASH_REMATCH[1]}"
      return 0
    elif [[ "$out" != *MANIFEST_UNKNOWN* && "$out" != *NAME_UNKNOWN* && "$out" != *"404"* ]]; then
      die "cannot look up $ref: $out"
    fi
    [ $((SECONDS - START_SECONDS)) -lt "$TIMEOUT" ] || { echo "$ref: not published within ${TIMEOUT}s, skipping" >&2; return 0; }
    sleep "$INTERVAL"
  done
}

# Replaces the digest of every `<pattern>@sha256:<old>` in file $1 with $3, reading <old> from the file
# itself. Stages the file and returns 0 (changed) when it differed, 1 (unchanged) otherwise.
repin_digest() {
  local file="$REPO_ROOT/$1" pattern="$2" new="$3" old
  [[ "$new" =~ ^sha256:[0-9a-f]{64}$ ]] || die "'$new' is not a sha256:<64 lowercase hex> digest"
  old="$(grep -oE "$pattern@sha256:[0-9a-f]{64}" "$file" | head -n1 | sed -E 's/.*@//')"
  [ -n "$old" ] || die "$1: no $pattern@sha256:... reference found"
  [ "$old" != "$new" ] || return 1
  sed -i "s|$pattern@$old|$pattern@$new|g" "$file"
  git -C "$REPO_ROOT" add "$1"
}

# Replaces the digest of the $2-th (0-indexed) `sha256.<old>: supported` line of file $1 (in the file's
# top-to-bottom order) with $3. Fixture-only deprecated/eol lines (absent from images/catalog.yaml) never
# match "supported" and are left untouched. Stages the file and returns 0 (changed) when it differed.
repin_supported_line() {
  local file="$REPO_ROOT/$1" index="$2" new="$3" old
  [[ "$new" =~ ^sha256:[0-9a-f]{64}$ ]] || die "'$new' is not a sha256:<64 lowercase hex> digest"
  old="$(grep -oE 'sha256\.[0-9a-f]{64}: supported' "$file" | sed -n "$((index + 1))p" | grep -oE 'sha256\.[0-9a-f]{64}')"
  [ -n "$old" ] || die "$1: no supported entry at index $index"
  new="${new#sha256:}"
  old="${old#sha256.}"
  [ "$old" != "$new" ] || return 1
  sed -i "s|sha256\.$old: supported|sha256.$new: supported|" "$file"
  git -C "$REPO_ROOT" add "$1"
}

# Opens a pull request from the files already staged in $REPO_ROOT, or does nothing when nothing changed.
# $1: branch name  $2: commit/PR title  $3: PR body
open_repin_pr() {
  local branch="$1" title="$2" body="$3" origin_ref
  if git -C "$REPO_ROOT" diff --cached --quiet; then
    echo "$title: nothing to re-pin"
    return 0
  fi
  git -C "$REPO_ROOT" config user.name "github-actions[bot]"
  git -C "$REPO_ROOT" config user.email "github-actions[bot]@users.noreply.github.com"
  origin_ref="$(git -C "$REPO_ROOT" symbolic-ref --quiet --short HEAD || git -C "$REPO_ROOT" rev-parse HEAD)"
  git -C "$REPO_ROOT" checkout -b "$branch"
  git -C "$REPO_ROOT" commit -m "$title"
  git -C "$REPO_ROOT" push origin "$branch"
  (cd "$REPO_ROOT" && gh pr create --base main --head "$branch" --title "$title" --body "$body")
  git -C "$REPO_ROOT" checkout --quiet "$origin_ref"
}

cmd_dockerfiles() {
  local name golden_name digest changed=0
  [ -f "$CATALOG" ] || die "$CATALOG not found"
  for name in "${!APP_DOCKERFILE[@]}"; do
    golden_name="${APP_GOLDEN[$name]}"
    digest="$(yq -r ".images[] | select(.name == \"$golden_name\" and .status == \"supported\") | .digest" "$CATALOG")"
    [ -n "$digest" ] || die "$CATALOG has no supported $golden_name entry"
    if repin_digest "${APP_DOCKERFILE[$name]}" "golden/$golden_name" "$digest"; then changed=1; fi
  done
  [ "$changed" -eq 1 ] || { echo "app Dockerfiles already pinned to the supported catalog digests"; return 0; }
  open_repin_pr "release-repin-dockerfiles-${GITHUB_RUN_ID:-$(date +%s)}" \
    "chore(release): re-pin app Dockerfiles to the supported golden digests" \
    "Automated: images/catalog.yaml's \`supported\` digests moved; re-pins the app Dockerfile FROM lines built on them so their next build (on this PR's merge) is signed by build-image.yml@refs/heads/main."
}

cmd_workloads() {
  local sha="${1:-$(git -C "$REPO_ROOT" rev-parse HEAD)}" name digest changed=0
  for name in "${!APP_WORKLOAD[@]}"; do
    digest="$(wait_for_digest "$REGISTRY/apps/$name:sha-$sha")"
    [ -n "$digest" ] || continue
    if repin_digest "${APP_WORKLOAD[$name]}" "apps/$name" "$digest"; then changed=1; fi
  done
  [ "$changed" -eq 1 ] || { echo "platform/workloads already pinned to the images built at $sha"; return 0; }
  open_repin_pr "release-repin-workloads-${GITHUB_RUN_ID:-$(date +%s)}" \
    "chore(release): re-pin platform workloads to the main-signed app builds" \
    "Automated: apps/*/Dockerfile now build on the supported golden digests; re-pins platform/workloads/*/*.yaml to the images build-image.yml published for commit $sha (signed by build-image.yml@refs/heads/main)."
}

cmd_fixtures() {
  local sha="${1:-$(git -C "$REPO_ROOT" rev-parse HEAD)}" digest current
  [ -f "$DEMO_FIXTURES" ] || die "$DEMO_FIXTURES not found"
  digest="$(wait_for_digest "$REGISTRY/fixtures/compliant:sha-$sha")"
  [ -n "$digest" ] || return 0
  current="$(yq -r '.commit' "$DEMO_FIXTURES")"
  [ "$current" != "$sha" ] || { echo "$DEMO_FIXTURES already pins commit $sha"; return 0; }
  yq -i ".commit = \"$sha\"" "$DEMO_FIXTURES"
  git -C "$REPO_ROOT" add "$(git -C "$REPO_ROOT" ls-files --full-name "$DEMO_FIXTURES")"
  open_repin_pr "release-repin-fixtures-${GITHUB_RUN_ID:-$(date +%s)}" \
    "chore(release): re-pin demo fixtures to the main-signed commit" \
    "Automated: fixtures.yml published the admission fixtures for commit $sha on main; re-pins images/demo-fixtures.yaml so \`task demo:*\` looks them up by that build."
}

cmd_e2e_params() {
  local python_digest file idx changed=0
  [ -f "$CATALOG" ] || die "$CATALOG not found"
  python_digest="$(yq -r '.images[] | select(.name == "python" and .status == "supported") | .digest' "$CATALOG")"
  [ -n "$python_digest" ] || die "$CATALOG has no supported python entry"
  for file in "${FIXTURE_DOCKERFILES[@]}"; do
    if repin_digest "$file" "golden/python" "$python_digest"; then changed=1; fi
  done

  mapfile -t supported_digests < <(yq -r '.images[] | select(.status == "supported") | .digest' "$CATALOG")
  [ "${#supported_digests[@]}" -ge 1 ] || die "$CATALOG has no supported entries"
  for file in "${E2E_GOLDEN_FILES[@]}"; do
    for idx in "${!supported_digests[@]}"; do
      if repin_supported_line "$file" "$idx" "${supported_digests[$idx]}"; then changed=1; fi
    done
  done

  [ "$changed" -eq 1 ] || { echo "E2E fixtures already pinned to the supported catalog digests"; return 0; }
  open_repin_pr "release-repin-e2e-params-${GITHUB_RUN_ID:-$(date +%s)}" \
    "chore(release): re-pin E2E fixtures to the supported golden digests" \
    "Automated: images/catalog.yaml's \`supported\` digests moved; re-pins the E2E fixture Dockerfiles and the Kyverno E2E params (tests/chainsaw/params/golden-images.yaml, tests/kyverno/workload/context.yaml) so policies CI keeps testing the digests admission actually enforces. Fixture-only deprecated/eol entries, absent from the catalog, are left untouched."
}

[ "$#" -ge 1 ] || die "usage: $0 dockerfiles | workloads [sha] | fixtures [sha] | e2e-params"
cmd="$1"
shift
case "$cmd" in
  dockerfiles) cmd_dockerfiles "$@" ;;
  workloads) cmd_workloads "${1:-}" ;;
  fixtures) cmd_fixtures "${1:-}" ;;
  e2e-params) cmd_e2e_params "$@" ;;
  *) die "usage: $0 dockerfiles | workloads [sha] | fixtures [sha] | e2e-params" ;;
esac
