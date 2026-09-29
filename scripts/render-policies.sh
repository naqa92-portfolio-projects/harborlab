#!/usr/bin/env bash
# Writes policies/ to <out-dir>/policies as Argo CD deploys it from git revision <revision>: off main, the
# workload build identity also trusts that branch, with the regexp the platform/apps chart renders.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$#" -eq 2 ] || die "usage: $0 <revision> <out-dir>"
revision="$1"
out="$2/policies"
[ -n "$revision" ] || die "empty revision"

mkdir -p "$out"
cp -R "$REPO_ROOT/policies/." "$out/"
[ "$revision" != main ] || exit 0

values="$(mktemp)"
trap 'rm -f "$values"' EXIT
# A values file, not --set: a branch name may hold characters --set parses (commas, dots, brackets).
jq -n --arg revision "$revision" '{revision: $revision}' >"$values"
identity="$(helm template root "$REPO_ROOT/platform/apps" -f "$values" --show-only templates/kyverno-policies.yaml |
  yq '.spec.source.kustomize.patches[0].patch' | yq '.[0].value')"
[[ "$identity" == ^https://* ]] || die "cannot read the build identity from platform/apps: $identity"

while IFS= read -r -d '' file; do
  if yq -e '.kind == "ImageValidatingPolicy" and (.metadata.name | test("^workload-"))' "$file" >/dev/null 2>&1; then
    IDENTITY="$identity" yq -i '.spec.attestors[0].cosign.keyless.identities[0].subjectRegExp = strenv(IDENTITY)' "$file"
  fi
done < <(find "$out" -type f -name '*.yaml' -print0)
