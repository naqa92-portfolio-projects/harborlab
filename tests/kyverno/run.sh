#!/usr/bin/env bash
# Runs `kyverno test --registry` on the suites of tests/kyverno (all, or those named as arguments).
# The CLI verifies signatures only on digest references and reads image metadata from its context, so
# each pod image tag is pinned to its current digest and each image's manifest and config are fetched
# from the registry into a temp copy of the suite; the committed context never holds image data.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLATFORM=linux/amd64

fail() {
  echo "$*" >&2
  exit 1
}

suites=("$@")
if [ "${#suites[@]}" -eq 0 ]; then
  mapfile -t suites < <(cd "$REPO_ROOT/tests/kyverno" &&
    find . -mindepth 2 -maxdepth 2 -name kyverno-test.yaml -printf '%h\n' | sed 's|^\./||' | sort)
fi
[ "${#suites[@]}" -gt 0 ] || fail "no kyverno test suite under tests/kyverno"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/tests"
cp -R "$REPO_ROOT/tests/kyverno" "$WORK/tests/kyverno"
# Suites name their policies as ../../../policies/<tier>/<file>; a missing directory is reported by kyverno.
[ ! -d "$REPO_ROOT/policies" ] || cp -R "$REPO_ROOT/policies" "$WORK/policies"

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
      digest="$(crane digest "$ref" 2>&1)" || fail "cannot resolve $ref (is the fixture published?): $digest"
      [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "unexpected digest for $ref: $digest"
      REF="$ref" PINNED="$ref@$digest" yq -i \
        '(.. | select(tag == "!!map" and has("image") and .image == strenv(REF)) | .image) = strenv(PINNED)' \
        "$dir/$file"
      echo "$ref@$digest" >>"$out"
    done < <(yq -N '.. | select(tag == "!!map" and has("image")) | .image' "$dir/$file")
  done < <(yq '.resources[]' "$dir/kyverno-test.yaml")
  sort -u -o "$out" "$out"
}

# Adds the registry's manifest and config of each image of $2 to the context file $1.
load_image_data() {
  local context="$1" refs="$2" ref manifest config entries="$WORK/images.json"
  echo '[]' >"$entries"
  while IFS= read -r ref; do
    manifest="$(crane manifest --platform "$PLATFORM" "$ref")" || fail "cannot fetch the manifest of $ref"
    config="$(crane config --platform "$PLATFORM" "$ref")" || fail "cannot fetch the config of $ref"
    jq --arg ref "$ref" --arg digest "${ref##*@}" --argjson manifest "$manifest" --argjson config "$config" \
      '. + [{image: $ref, resolvedImage: $ref, digest: $digest, manifest: $manifest, config: $config}]' \
      "$entries" >"$entries.new"
    mv "$entries.new" "$entries"
  done <"$refs"
  ENTRIES="$entries" yq -i '.spec.images = load(strenv(ENTRIES))' "$context"
}

status=0
for suite in "${suites[@]}"; do
  dir="$WORK/tests/kyverno/$suite"
  [ -f "$dir/kyverno-test.yaml" ] || fail "tests/kyverno/$suite has no kyverno-test.yaml"
  context_file="$(yq '.context // ""' "$dir/kyverno-test.yaml")"
  [ -n "$context_file" ] || fail "tests/kyverno/$suite/kyverno-test.yaml declares no context file"
  context="$dir/$context_file"
  yq -e '.spec.images == null' "$context" >/dev/null ||
    fail "tests/kyverno/$suite/$context_file mocks image data: image metadata must come from the registry"

  echo "== kyverno test tests/kyverno/$suite"
  pin_images "$dir" "$WORK/$suite.refs"
  load_image_data "$context" "$WORK/$suite.refs"
  kyverno test "$dir" --registry --remove-color --detailed-results || status=1
done
exit "$status"
