#!/usr/bin/env bash
# Publishes the admission fixtures under <prefix>/fixtures and <prefix>/offlist from the images
# build-image.yml pushed as `sha-<commit>`: the copies get that immutable tag too, and every fixture the
# moving `e2e` tag. Referrers live in the `sha256-<hex>` fallback tag (GHCR has no referrers API), so each
# copy chooses which bundles it carries.
set -euo pipefail

PREFIX="${1:?usage: $0 <registry prefix, e.g. ghcr.io/owner/harborlab> <commit sha>}"
SHA="${2:?usage: $0 <registry prefix> <commit sha>}"
BUILT=(compliant missing-labels deprecated-base eol-base unknown-base demo-deprecated-base demo-eol-base)
SIGNATURE_TYPE=https://sigstore.dev/cosign/sign/v1
PROVENANCE_TYPE=https://slsa.dev/provenance/v1

for name in "${BUILT[@]}"; do
  digest="$(crane digest "$PREFIX/fixtures/$name:sha-$SHA")"
  crane tag "$PREFIX/fixtures/$name@$digest" e2e
  echo "fixtures/$name:e2e -> $digest"
done

SOURCE="$PREFIX/fixtures/compliant"
DIGEST="$(crane digest "$SOURCE:sha-$SHA")"
REFERRERS_TAG="sha256-${DIGEST#sha256:}"
mapfile -t REFERRERS < <(crane manifest "$SOURCE:$REFERRERS_TAG" | jq -r '.manifests[].digest')
[ "${#REFERRERS[@]}" -gt 0 ] || { echo "$SOURCE@$DIGEST has no referrer" >&2; exit 1; }

# Same digest, no referrer at all.
crane copy "$SOURCE@$DIGEST" "$PREFIX/fixtures/unsigned:e2e"
crane tag "$PREFIX/fixtures/unsigned@$DIGEST" "sha-$SHA"

# Same digest outside the workload allow-list, with every referrer.
crane copy "$SOURCE@$DIGEST" "$PREFIX/offlist/compliant:e2e"
crane tag "$PREFIX/offlist/compliant@$DIGEST" "sha-$SHA"
crane copy "$SOURCE:$REFERRERS_TAG" "$PREFIX/offlist/compliant:$REFERRERS_TAG"

# Same digest with the build-image.yml signature and SLSA provenance only.
target="$PREFIX/fixtures/no-sbom"
crane copy "$SOURCE@$DIGEST" "$target:e2e"
crane tag "$target@$DIGEST" "sha-$SHA"
kept=()
for referrer in "${REFERRERS[@]}"; do
  type="$(crane manifest "$SOURCE@$referrer" | jq -r '.annotations["dev.sigstore.bundle.predicateType"] // ""')"
  if [ "$type" = "$SIGNATURE_TYPE" ] || [ "$type" = "$PROVENANCE_TYPE" ]; then
    crane copy "$SOURCE@$referrer" "$target@$referrer"
    kept+=(--manifest "$target@$referrer")
  fi
done
[ "${#kept[@]}" -eq 4 ] || { echo "$SOURCE@$DIGEST lacks its signature or SLSA provenance bundle" >&2; exit 1; }
crane index append "${kept[@]}" --tag "$target:$REFERRERS_TAG"

# Same digest signed and attested by the identity running this script, not by build-image.yml.
target="$PREFIX/fixtures/foreign-signer"
crane copy "$SOURCE@$DIGEST" "$target:e2e"
crane tag "$target@$DIGEST" "sha-$SHA"
if crane digest "$target:$REFERRERS_TAG" >/dev/null 2>&1; then
  echo "fixtures/foreign-signer@$DIGEST is already signed"
else
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  ref="$target@$DIGEST"
  syft scan "registry:$ref" -o "cyclonedx-json=$work/sbom.cdx.json" -o "spdx-json=$work/sbom.spdx.json"
  jq -n --arg digest "${DIGEST#sha256:}" --arg sha "$SHA" '{
      buildDefinition: {
        buildType: "https://actions.github.io/buildtypes/workflow/v1",
        externalParameters: {workflow: {path: ".github/workflows/fixtures.yml"}},
        resolvedDependencies: [{uri: "oci://fixtures/compliant", digest: {sha256: $digest}}]
      },
      runDetails: {builder: {id: "fixtures.yml"}, metadata: {invocationId: $sha}}
    }' >"$work/provenance.json"
  cosign sign --yes "$ref"
  cosign attest --yes --type cyclonedx --predicate "$work/sbom.cdx.json" "$ref"
  cosign attest --yes --type spdxjson --predicate "$work/sbom.spdx.json" "$ref"
  cosign attest --yes --type slsaprovenance1 --predicate "$work/provenance.json" "$ref"
fi
echo "published unsigned, offlist/compliant, no-sbom and foreign-signer at $DIGEST"
