#!/usr/bin/env bats
# The build identity admission and dt-bridge trust, read statically: build-image.yml run from main of this
# repository only. Identity regular expressions are exercised on certificate SANs with jq (Oniguruma), whose
# syntax covers the RE2 subset the policies use.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
BUILD_WORKFLOW=.github/workflows/build-image.yml
REPOSITORY=naqa92-portfolio-projects/harborlab
SIGNATURE_POLICY=policies/workload/image-signature.yaml
DT_BRIDGE_MANIFEST=platform/workloads/dt-bridge/dt-bridge.yaml
SAN_MAIN="https://github.com/$REPOSITORY/.github/workflows/build-image.yml@refs/heads/main"
SAN_PRD_BRANCH="https://github.com/$REPOSITORY/.github/workflows/build-image.yml@refs/heads/prd-999-any-branch"
SAN_OTHER_REF="https://github.com/$REPOSITORY/.github/workflows/build-image.yml@refs/heads/feature"
SAN_FOREIGN_REPO="https://github.com/attacker-example/harborlab/.github/workflows/build-image.yml@refs/heads/main"

fail() {
  echo "$*" >&2
  return 1
}

# The build-image identities (subject or subjectRegExp of a keyless attestor) of every policy under
# policies/, one "<file>|<regexp>" per line; a literal subject becomes an anchored, escaped regexp.
build_identities() {
  local file
  for file in "$REPO_ROOT"/policies/*/*.yaml; do
    yq -o=json '.' "$file" | jq -r --arg f "${file#"$REPO_ROOT/"}" '
      [.. | objects | select(has("subjectRegExp") or has("subject"))
        | (.subjectRegExp // ("^" + (.subject | gsub("(?<c>[.^$*+?()\\[\\]{}|\\\\])"; "\\\(.c)")) + "$"))]
      | map(select(test("build-image")))[] | "\($f)|\(.)"'
  done
}

# Asserts regexp $2 (from $1) accepts main of this repository and nothing else it is asked about.
assert_main_only() {
  local where="$1" regexp="$2" san
  jq -en --arg r "$regexp" --arg s "$SAN_MAIN" '$s | test($r)' >/dev/null ||
    fail "$where: identity $regexp does not accept $SAN_MAIN"
  for san in "$SAN_PRD_BRANCH" "$SAN_OTHER_REF" "$SAN_FOREIGN_REPO"; do
    ! jq -en --arg r "$regexp" --arg s "$san" '$s | test($r)' >/dev/null ||
      fail "$where: identity $regexp accepts $san (only main of $REPOSITORY is trusted in git)"
  done
}

@test "committed admission policies trust build-image.yml from main only" {
  run build_identities
  [ "$status" -eq 0 ] || fail "cannot read the policies: $output"
  [ -n "$output" ] || fail "no policy under policies/ declares a build-image.yml identity"
  while IFS='|' read -r file regexp; do
    assert_main_only "$file" "$regexp"
  done <<<"$output"
}

@test "committed dt-bridge signer identities trust main only" {
  run yq -o=json '.' "$REPO_ROOT/$DT_BRIDGE_MANIFEST"
  [ "$status" -eq 0 ] || fail "$DT_BRIDGE_MANIFEST is not valid YAML"
  identities="$(jq -rs '[.[] | .. | objects | select(.name? | strings | test("^SIGNER_IDENTITY_"))
    | "\(.name)|\(.value // "")"][]' <<<"$output")"
  [ -n "$identities" ] || fail "$DT_BRIDGE_MANIFEST sets no SIGNER_IDENTITY_* variable"
  while IFS='|' read -r name regexp; do
    [ -n "$regexp" ] || fail "$DT_BRIDGE_MANIFEST: $name has no literal value"
    # dt-bridge matches the whole SAN (re.fullmatch).
    assert_main_only "$DT_BRIDGE_MANIFEST $name" "^(?:$regexp)\$"
  done <<<"$identities"
}

@test "build-image.yml signs only when called from this repository" {
  run yq -o=json '.jobs' "$REPO_ROOT/$BUILD_WORKFLOW"
  [ "$status" -eq 0 ] || fail "$BUILD_WORKFLOW is not valid YAML"
  # Every job allowed to mint an OIDC token (keyless signing) is guarded on the caller repository:
  # in a reusable workflow, github.repository is the caller's.
  unguarded="$(jq -r --arg repo "$REPOSITORY" 'to_entries[]
    | select(.value.permissions["id-token"]? == "write")
    | select((.value.if // "" | tostring
        | test("github\\.repository\\s*==\\s*[\u0027\"]" + ($repo | gsub("\\."; "\\.")) + "[\u0027\"]")) | not)
    | .key' <<<"$output")"
  signing="$(jq -r 'to_entries[] | select(.value.permissions["id-token"]? == "write") | .key' <<<"$output")"
  [ -n "$signing" ] || fail "$BUILD_WORKFLOW has no job with id-token: write"
  [ -z "$unguarded" ] ||
    fail "$BUILD_WORKFLOW jobs mint an OIDC token without an if: github.repository == '$REPOSITORY' guard: $unguarded"
}

@test "workload signature policy binds the verified provenance to this repository" {
  run yq -o=json '.' "$REPO_ROOT/$SIGNATURE_POLICY"
  [ "$status" -eq 0 ] || fail "$SIGNATURE_POLICY is not valid YAML"
  policy="$output"
  # A certificate extension match (keyless.additionalExtensions) is not enforced by ImageValidatingPolicy
  # (kyverno/kyverno#15809): the repository must be checked on the verified SLSA provenance instead,
  # whose externalParameters.workflow.repository build-image.yml fills from the caller repository.
  jq -e '.spec.attestations[]? | select(.intoto.type == "https://slsa.dev/provenance/v1")' <<<"$policy" >/dev/null ||
    fail "$SIGNATURE_POLICY verifies no SLSA provenance attestation"
  expressions="$(jq -r '[(.spec.variables // [])[].expression, (.spec.validations // [])[].expression] | .[]' <<<"$policy")"
  grep -q 'extractPayload' <<<"$expressions" ||
    fail "$SIGNATURE_POLICY reads no verified attestation payload (extractPayload) in its CEL expressions"
  grep -qF "github.com/$REPOSITORY" <<<"$expressions" ||
    fail "$SIGNATURE_POLICY CEL expressions never compare the verified provenance with https://github.com/$REPOSITORY"
}
