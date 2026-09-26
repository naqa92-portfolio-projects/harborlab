# Golden images published by golden.yml for the checked-out history, and their cosign checks.
# The branch comes from GOLDEN_REF (refs/heads/<branch>) or the checked-out branch.

GITHUB_REPO=naqa92-portfolio-projects/harborlab
GHCR_GOLDEN="ghcr.io/$GITHUB_REPO/golden"
GOLDEN_IMAGES=(python java)
GOLDEN_WORKFLOW=golden.yml
GOLDEN_INPUTS=images/golden
DHI_STEP="Verify DHI base signature"
OIDC_ISSUER=https://token.actions.githubusercontent.com
FOREIGN_IDENTITY='^https://github\.com/sigstore/cosign/\.github/workflows/.+$'
# Same repository, another workflow: the identity is bound to the workflow file, not only the repo.
OTHER_WORKFLOW_IDENTITY='^https://github\.com/naqa92-portfolio-projects/harborlab/\.github/workflows/spike\.yml@.+$'

fail() {
  echo "$*" >&2
  return 1
}

regex_escape() {
  sed -e 's/[][\.*^$+?(){}|]/\\&/g' <<<"$1"
}

# Sets GOLDEN_REF, GOLDEN_BRANCH, GOLDEN_RUN_ID and GOLDEN_SHA: the latest successful golden.yml run
# on the branch whose commit is in the checked-out history and contains the last change to
# images/golden, so the images it published are those of the checked-out golden sources.
resolve_golden_run() {
  local branch last_change runs id sha
  if [ -n "${GOLDEN_REF:-}" ]; then
    [[ "$GOLDEN_REF" == refs/heads/?* ]] || fail "GOLDEN_REF '$GOLDEN_REF' is not refs/heads/<branch>"
  else
    branch="$(git -C "$REPO_ROOT" symbolic-ref --quiet --short HEAD)" ||
      fail "detached HEAD: set GOLDEN_REF=refs/heads/<branch>"
    GOLDEN_REF="refs/heads/$branch"
  fi
  GOLDEN_BRANCH="${GOLDEN_REF#refs/heads/}"

  last_change="$(git -C "$REPO_ROOT" log -1 --format=%H -- "$GOLDEN_INPUTS")"
  [ -n "$last_change" ] || fail "no commit touches $GOLDEN_INPUTS in the checked-out history"

  runs="$(gh api -X GET "repos/$GITHUB_REPO/actions/workflows/$GOLDEN_WORKFLOW/runs" \
    -f branch="$GOLDEN_BRANCH" -f status=success -f per_page=100 \
    --jq '.workflow_runs[] | "\(.id) \(.head_sha)"' 2>&1)" ||
    fail "cannot list $GOLDEN_WORKFLOW runs of $GITHUB_REPO on $GOLDEN_BRANCH: $runs"

  while read -r id sha; do
    [ -n "$id" ] || continue
    if git -C "$REPO_ROOT" merge-base --is-ancestor "$last_change" "$sha" 2>/dev/null &&
      git -C "$REPO_ROOT" merge-base --is-ancestor "$sha" HEAD 2>/dev/null; then
      GOLDEN_RUN_ID="$id"
      GOLDEN_SHA="$sha"
      return 0
    fi
  done <<<"$runs"
  fail "no successful $GOLDEN_WORKFLOW run on $GOLDEN_BRANCH at a commit between ${last_change:0:12} (last change to $GOLDEN_INPUTS) and HEAD"
}

# Digest of the golden image $1 that the resolved run pushed as tag sha-<commit>. Called in a
# command substitution, where errexit does not apply: every failure returns explicitly.
golden_ghcr_digest() {
  local image="$GHCR_GOLDEN/$1:sha-$GOLDEN_SHA" digest
  digest="$(crane digest "$image" 2>&1)" || {
    fail "golden image $image not found on GHCR: $digest"
    return 1
  }
  [[ "$digest" == sha256:* ]] || {
    fail "no digest for $image: $digest"
    return 1
  }
  echo "$digest"
}

# Signing identity of this repository's golden build on GOLDEN_REF (golden.yml, or build-image.yml
# when golden.yml calls it as a reusable workflow).
golden_identity() {
  printf '^https://github\\.com/%s/\\.github/workflows/(golden|build-image)\\.yml@%s$' \
    "$(regex_escape "$GITHUB_REPO")" "$(regex_escape "$GOLDEN_REF")"
}

golden_cosign_args() {
  GOLDEN_COSIGN=(--certificate-oidc-issuer "$OIDC_ISSUER" --certificate-identity-regexp "$(golden_identity)"
    --certificate-github-workflow-repository "$GITHUB_REPO" --certificate-github-workflow-sha "$GOLDEN_SHA")
}

# Decoded in-toto statements of a `cosign verify-attestation` output, as one JSON array.
attestation_statements() {
  jq -s 'map(.payload | @base64d | fromjson)' "$1"
}

# Signature, CycloneDX, SPDX and SLSA v1 attestations of $1 verify against the golden identity at
# GOLDEN_SHA; the SBOMs are non-empty and the provenance names the built commit. Extra cosign flags
# (e.g. --registry-cacert) follow the reference.
verify_golden_signed_and_attested() {
  local ref="$1" type err="$BATS_TEST_TMPDIR/cosign.err"
  shift
  golden_cosign_args
  cosign verify "${GOLDEN_COSIGN[@]}" "$@" "$ref" >/dev/null 2>"$err" ||
    fail "cosign verify failed on $ref against $(golden_identity) at ${GOLDEN_SHA:0:12}: $(tail -n 5 "$err")"
  for type in cyclonedx spdxjson slsaprovenance1; do
    cosign verify-attestation "${GOLDEN_COSIGN[@]}" "$@" --type "$type" "$ref" \
      >"$BATS_TEST_TMPDIR/attestation-$type.json" 2>"$err" ||
      fail "$type attestation not verified on $ref against $(golden_identity): $(tail -n 5 "$err")"
  done

  attestation_statements "$BATS_TEST_TMPDIR/attestation-cyclonedx.json" |
    jq -e 'any(.[]; (.predicate.components // []) | length > 0)' >/dev/null ||
    fail "the CycloneDX attestation of $ref lists no component"
  attestation_statements "$BATS_TEST_TMPDIR/attestation-spdxjson.json" |
    jq -e 'any(.[]; (.predicate.packages // []) | length > 0)' >/dev/null ||
    fail "the SPDX attestation of $ref lists no package"
  attestation_statements "$BATS_TEST_TMPDIR/attestation-slsaprovenance1.json" |
    jq -e --arg sha "$GOLDEN_SHA" \
      'any(.[]; any(.predicate.buildDefinition.resolvedDependencies[]?; .digest.gitCommit == $sha))' >/dev/null ||
    fail "the SLSA provenance of $ref does not record the built commit $GOLDEN_SHA in resolvedDependencies"
}

# The signature of $1 is rejected for identities other than this repository's golden build.
refute_foreign_identities() {
  local ref="$1" identity
  shift
  for identity in "$FOREIGN_IDENTITY" "$OTHER_WORKFLOW_IDENTITY"; do
    if cosign verify --certificate-oidc-issuer "$OIDC_ISSUER" --certificate-identity-regexp "$identity" \
      "$@" "$ref" >/dev/null 2>&1; then
      fail "cosign verify accepted $ref for the identity $identity"
    fi
  done
}
