#!/usr/bin/env bash
# Runs `kyverno test --registry` on every suite under tests/kyverno (or the suite directories named as
# arguments, relative to tests/kyverno) and fails if any suite fails; each suite loads one policy.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLATFORM=linux/amd64
# A hung CLI fails its suite instead of eating the CI job timeout.
SUITE_TIMEOUT="${KYVERNO_SUITE_TIMEOUT:-600}"
# Anonymous pulls from shared runners hit registry rate limits; only that error class is retried.
RATE_LIMIT_ATTEMPTS="${REGISTRY_RATE_LIMIT_ATTEMPTS:-4}"
RATE_LIMIT_BACKOFF="${REGISTRY_RATE_LIMIT_BACKOFF:-15}"
RATE_LIMIT_PATTERN='TOOMANYREQUESTS|429 Too Many Requests'

fail() {
  echo "$*" >&2
  exit 1
}

suites=("$@")
if [ "${#suites[@]}" -eq 0 ]; then
  mapfile -t suites < <(cd "$REPO_ROOT/tests/kyverno" &&
    find . -name kyverno-test.yaml -printf '%h\n' | sed 's|^\./||' | sort)
fi
[ "${#suites[@]}" -gt 0 ] || fail "no kyverno test suite under tests/kyverno"

# The fixtures are signed by build-image.yml on the branch under test: the policies trust that revision as
# the platform deployed from it does. CI sets HARBORLAB_REVISION; locally it is the checked-out branch.
REVISION="${HARBORLAB_REVISION:-$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)}"
[ -n "$REVISION" ] && [ "$REVISION" != HEAD ] ||
  fail "cannot tell the revision the fixtures were signed on (detached HEAD): set HARBORLAB_REVISION"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/tests"
cp -R "$REPO_ROOT/tests/kyverno" "$WORK/tests/kyverno"
# Fixture images are named by the immutable tag pinned in images/demo-fixtures.yaml, never by `e2e`.
while IFS= read -r -d '' file; do
  "$REPO_ROOT/tests/fixtures/fixture-tag.sh" "$file" >"$file.rendered" || fail "cannot set the fixture tag in $file"
  mv "$file.rendered" "$file"
done < <(find "$WORK/tests/kyverno" -name '*.yaml' -print0)
# Suites name their policies relative to the repo root copy; a missing policy file is reported by kyverno.
"$REPO_ROOT/scripts/render-policies.sh" "$REVISION" "$WORK" ||
  fail "cannot render the policies for revision $REVISION"

# Runs "$@", retrying with exponential backoff only while it fails with a registry rate-limit error.
# A timeout (exit 124 or 137) or any other failure is returned at once; the last attempt's result stands.
retry_rate_limited() {
  local attempt=1 delay="$RATE_LIMIT_BACKOFF" out err rc
  out="$(mktemp -p "$WORK")"
  err="$(mktemp -p "$WORK")"
  while :; do
    rc=0
    "$@" >"$out" 2>"$err" || rc=$?
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] || [ "$attempt" -ge "$RATE_LIMIT_ATTEMPTS" ] ||
      ! grep -qiE "$RATE_LIMIT_PATTERN" "$out" "$err"; then
      cat "$out"
      cat "$err" >&2
      return "$rc"
    fi
    cat "$err" >&2
    echo "registry rate limit on attempt $attempt/$RATE_LIMIT_ATTEMPTS of: $*; retrying in ${delay}s" >&2
    sleep "$delay"
    delay=$((delay * 2))
    attempt=$((attempt + 1))
  done
}

# Writes the pinned references of every pod image of the suite's resources to $2, one per line, and
# pins tag-only references in place.
pin_images() {
  local dir="$1" out="$2" file ref digest
  : >"$out"
  while IFS= read -r file; do
    [ -f "$dir/$file" ] || fail "$dir/$file: resource file listed in kyverno-test.yaml does not exist"
    while IFS= read -r ref; do
      [ -n "$ref" ] || continue
      if [[ "$ref" == *@sha256:* ]]; then
        echo "$ref" >>"$out"
        continue
      fi
      digest="$(retry_rate_limited crane digest "$ref" 2>&1)" ||
        fail "cannot resolve $ref (is the fixture published?): $digest"
      [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "unexpected digest for $ref: $digest"
      REF="$ref" PINNED="$ref@$digest" yq -i \
        '(.. | select(tag == "!!map" and has("image") and .image == strenv(REF)) | .image) = strenv(PINNED)' \
        "$dir/$file"
      echo "$ref@$digest" >>"$out"
    done < <(yq -N '.. | select(tag == "!!map" and has("image")) | .image' "$dir/$file")
  done < <(yq '.resources[]' "$dir/kyverno-test.yaml")
  sort -u -o "$out" "$out"
}

# Sets the registry's manifest and config of each image of $2 as the image data of the context file $1.
load_image_data() {
  local context="$1" refs="$2" ref manifest config entries="$WORK/images.json"
  echo '[]' >"$entries"
  while IFS= read -r ref; do
    manifest="$(retry_rate_limited crane manifest --platform "$PLATFORM" "$ref")" ||
      fail "cannot fetch the manifest of $ref"
    config="$(retry_rate_limited crane config --platform "$PLATFORM" "$ref")" ||
      fail "cannot fetch the config of $ref"
    jq --arg ref "$ref" --arg digest "${ref##*@}" --argjson manifest "$manifest" --argjson config "$config" \
      '. + [{image: $ref, resolvedImage: $ref, digest: $digest, manifest: $manifest, config: $config}]' \
      "$entries" >"$entries.new"
    mv "$entries.new" "$entries"
  done <"$refs"
  ENTRIES="$entries" yq -i '.spec.images = load(strenv(ENTRIES))' "$context"
}

failed=()
for suite in "${suites[@]}"; do
  suite="${suite%/}"
  dir="$WORK/tests/kyverno/$suite"
  [ -f "$dir/kyverno-test.yaml" ] || fail "tests/kyverno/$suite has no kyverno-test.yaml"
  [ "$(yq '.policies | length' "$dir/kyverno-test.yaml")" -eq 1 ] ||
    fail "tests/kyverno/$suite/kyverno-test.yaml must load exactly one policy"
  context_file="$(yq '.context // ""' "$dir/kyverno-test.yaml")"
  [ -n "$context_file" ] || fail "tests/kyverno/$suite/kyverno-test.yaml declares no context file"
  context="$dir/$context_file"
  yq -e '.spec.images == null' "$REPO_ROOT/tests/kyverno/$suite/$context_file" >/dev/null ||
    fail "tests/kyverno/$suite/$context_file mocks image data: image metadata must come from the registry"

  echo "== kyverno test tests/kyverno/$suite"
  refs="$WORK/${suite//\//_}.refs"
  pin_images "$dir" "$refs"
  load_image_data "$context" "$refs"
  rc=0
  retry_rate_limited timeout --kill-after=10 "$SUITE_TIMEOUT" \
    kyverno test "$dir" --registry --remove-color --detailed-results || rc=$?
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    echo "tests/kyverno/$suite: kyverno test did not finish within ${SUITE_TIMEOUT}s" >&2
  fi
  [ "$rc" -eq 0 ] || failed+=("$suite")
done

if [ "${#failed[@]}" -gt 0 ]; then
  echo "failed kyverno test suites: ${failed[*]}" >&2
  exit 1
fi
echo "all ${#suites[@]} kyverno test suites passed"
