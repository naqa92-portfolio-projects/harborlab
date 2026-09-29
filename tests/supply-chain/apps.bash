# Golden-path app images built by their own workflow through build-image.yml, for the checked-out
# history, and their cosign checks. Load after golden.bash (fail, regex_escape, attestation helpers).

APP_NAMES=(dt-bridge hello-java)
GHCR_APPS="ghcr.io/$GITHUB_REPO/apps"
BUILD_WORKFLOW_FILE=.github/workflows/build-image.yml
CATALOG_FILE=images/catalog.yaml

# First image of the last FROM of a Dockerfile read on stdin (flags such as --platform skipped).
final_from() {
  awk 'toupper($1) == "FROM" { image = ""; for (i = 2; i <= NF; i++) if ($i !~ /^--/) { image = $i; break } }
    END { print image }'
}

# Sets APP_REF, APP_BRANCH, APP_RUN_ID and APP_SHA for app $1: the latest successful run of
# .github/workflows/<app>.yml on the branch of GOLDEN_REF (or the checked-out branch) whose commit is
# in the checked-out history and contains the last change to apps/<app> or to that workflow.
resolve_app_run() {
  local app="$1" branch last_change runs id sha
  APP_REF="${GOLDEN_REF:-}"
  if [ -n "$APP_REF" ]; then
    [[ "$APP_REF" == refs/heads/?* ]] || fail "ref '$APP_REF' is not refs/heads/<branch>"
  else
    branch="$(git -C "$REPO_ROOT" symbolic-ref --quiet --short HEAD)" ||
      fail "detached HEAD: set GOLDEN_REF=refs/heads/<branch>"
    APP_REF="refs/heads/$branch"
  fi
  APP_BRANCH="${APP_REF#refs/heads/}"

  last_change="$(git -C "$REPO_ROOT" log -1 --format=%H -- "apps/$app" ".github/workflows/$app.yml")"
  [ -n "$last_change" ] || fail "no commit touches apps/$app or .github/workflows/$app.yml in the checked-out history"

  runs="$(gh api -X GET "repos/$GITHUB_REPO/actions/workflows/$app.yml/runs" \
    -f branch="$APP_BRANCH" -f status=success -f per_page=100 \
    --jq '.workflow_runs[] | "\(.id) \(.head_sha)"' 2>&1)" ||
    fail "cannot list $app.yml runs of $GITHUB_REPO on $APP_BRANCH: $runs"

  while read -r id sha; do
    [ -n "$id" ] || continue
    if git -C "$REPO_ROOT" merge-base --is-ancestor "$last_change" "$sha" 2>/dev/null &&
      git -C "$REPO_ROOT" merge-base --is-ancestor "$sha" HEAD 2>/dev/null; then
      APP_RUN_ID="$id"
      APP_SHA="$sha"
      return 0
    fi
  done <<<"$runs"
  fail "no successful $app.yml run on $APP_BRANCH at a commit between ${last_change:0:12} (last change to apps/$app) and HEAD"
}

# Digest of app $1 pushed by the resolved run as tag sha-<commit>. Called in a command substitution,
# where errexit does not apply: every failure returns explicitly.
app_ghcr_digest() {
  local image="$GHCR_APPS/$1:sha-$APP_SHA" digest
  digest="$(crane digest "$image" 2>&1)" || {
    fail "app image $image not found on GHCR: $digest"
    return 1
  }
  [[ "$digest" == sha256:* ]] || {
    fail "no digest for $image: $digest"
    return 1
  }
  echo "$digest"
}

# Signing identity of the platform's reusable build on APP_REF: build-image.yml only, never the app's
# own caller workflow.
app_identity() {
  printf '^https://github\\.com/%s/\\.github/workflows/build-image\\.yml@%s$' \
    "$(regex_escape "$GITHUB_REPO")" "$(regex_escape "$APP_REF")"
}

app_cosign_args() {
  APP_COSIGN=(--certificate-oidc-issuer "$OIDC_ISSUER" --certificate-identity-regexp "$(app_identity)"
    --certificate-github-workflow-repository "$GITHUB_REPO" --certificate-github-workflow-sha "$APP_SHA")
}

# Signature, CycloneDX, SPDX and SLSA v1 attestations of $2 (an image of app $1) verify against the
# build-image.yml identity at APP_SHA; the SBOMs are non-empty; the provenance records the commit and
# exactly one oci:// base, the final FROM digest of apps/<app>/Dockerfile at that commit, which is a
# supported entry of the catalog. Extra cosign flags (e.g. --registry-cacert) follow the reference.
verify_app_signed_and_attested() {
  local app="$1" ref="$2" type err="$BATS_TEST_TMPDIR/cosign.err" from bases base_hex status
  shift 2
  app_cosign_args
  cosign verify "${APP_COSIGN[@]}" "$@" "$ref" >/dev/null 2>"$err" ||
    fail "cosign verify failed on $ref against $(app_identity) at ${APP_SHA:0:12}: $(tail -n 5 "$err")"
  for type in cyclonedx spdxjson slsaprovenance1; do
    cosign verify-attestation "${APP_COSIGN[@]}" "$@" --type "$type" "$ref" \
      >"$BATS_TEST_TMPDIR/attestation-$type.json" 2>"$err" ||
      fail "$type attestation not verified on $ref against $(app_identity): $(tail -n 5 "$err")"
  done

  attestation_statements "$BATS_TEST_TMPDIR/attestation-cyclonedx.json" |
    jq -e 'any(.[]; (.predicate.components // []) | length > 0)' >/dev/null ||
    fail "the CycloneDX attestation of $ref lists no component"
  attestation_statements "$BATS_TEST_TMPDIR/attestation-spdxjson.json" |
    jq -e 'any(.[]; (.predicate.packages // []) | length > 0)' >/dev/null ||
    fail "the SPDX attestation of $ref lists no package"
  attestation_statements "$BATS_TEST_TMPDIR/attestation-slsaprovenance1.json" |
    jq -e --arg sha "$APP_SHA" \
      'any(.[]; any(.predicate.buildDefinition.resolvedDependencies[]?; .digest.gitCommit == $sha))' >/dev/null ||
    fail "the SLSA provenance of $ref does not record the built commit $APP_SHA in resolvedDependencies"

  mapfile -t bases < <(attestation_statements "$BATS_TEST_TMPDIR/attestation-slsaprovenance1.json" |
    jq -r '[.[].predicate.buildDefinition.resolvedDependencies[]? | select((.uri // "") | startswith("oci://"))
      | .digest.sha256 // ""] | unique[]')
  [ "${#bases[@]}" -eq 1 ] ||
    fail "the SLSA provenance of $ref records ${#bases[@]} oci:// base(s), expected exactly one: ${bases[*]}"
  base_hex="${bases[0]}"

  from="$(git -C "$REPO_ROOT" show "$APP_SHA:apps/$app/Dockerfile" 2>/dev/null | final_from)"
  [[ "$from" == *@sha256:* ]] ||
    fail "apps/$app/Dockerfile at ${APP_SHA:0:12} has no digest-pinned final FROM: '$from'"
  [ "${from##*@sha256:}" = "$base_hex" ] ||
    fail "the SLSA provenance of $ref names base sha256:$base_hex, not the final FROM $from of apps/$app/Dockerfile"

  status="$(yq -r ".images[] | select(.digest == \"sha256:$base_hex\") | .status" "$REPO_ROOT/$CATALOG_FILE" | sort -u)"
  [ "$status" = supported ] ||
    fail "base sha256:$base_hex of $ref is not a supported entry of $CATALOG_FILE (status: '${status:-absent}')"
}

# The signature of $2 (an image of app $1) is rejected for identities other than build-image.yml,
# including the app's own caller workflow.
refute_app_foreign_identities() {
  local app="$1" ref="$2" caller
  shift 2
  refute_foreign_identities "$ref" "$@"
  caller="^https://github\\.com/$(regex_escape "$GITHUB_REPO")/\\.github/workflows/$(regex_escape "$app")\\.yml@.+$"
  if cosign verify --certificate-oidc-issuer "$OIDC_ISSUER" --certificate-identity-regexp "$caller" \
    "$@" "$ref" >/dev/null 2>&1; then
    fail "cosign verify accepted $ref for the app caller identity $caller: the signer must be build-image.yml"
  fi
}
