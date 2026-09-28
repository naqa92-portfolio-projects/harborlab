#!/usr/bin/env bash
# Prints the immutable tag `sha-<commit>` of the admission fixtures pinned in images/demo-fixtures.yaml;
# given files, prints them with every ${FIXTURE_TAG} replaced by that tag.
set -euo pipefail

PIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/images/demo-fixtures.yaml"

commit="$(yq '.commit' "$PIN")"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
  echo "$PIN: .commit '$commit' is not a full commit sha" >&2
  exit 1
}
tag="sha-$commit"

if [ "$#" -eq 0 ]; then
  echo "$tag"
  exit 0
fi
for file in "$@"; do
  sed "s/\${FIXTURE_TAG}/$tag/g" "$file"
done
