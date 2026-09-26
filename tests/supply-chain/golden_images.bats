#!/usr/bin/env bats
# Golden images on GHCR, live: keyless signature and attestations bound to this repository's golden
# build of the checked-out commit, and the DHI base signature checked by the build and here.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
load golden

DHI_PUBLIC_KEY_URL=https://dhi.io/keyring/latest.pub

@test "golden python is signed with CycloneDX, SPDX and SLSA attestations by this repo's workflow" {
  resolve_golden_run
  digest="$(golden_ghcr_digest python)"
  verify_golden_signed_and_attested "$GHCR_GOLDEN/python@$digest"
}

@test "golden java is signed with CycloneDX, SPDX and SLSA attestations by this repo's workflow" {
  resolve_golden_run
  digest="$(golden_ghcr_digest java)"
  verify_golden_signed_and_attested "$GHCR_GOLDEN/java@$digest"
}

@test "golden image verification fails against a foreign identity" {
  resolve_golden_run
  golden_cosign_args
  for name in "${GOLDEN_IMAGES[@]}"; do
    digest="$(golden_ghcr_digest "$name")"
    ref="$GHCR_GOLDEN/$name@$digest"
    run cosign verify "${GOLDEN_COSIGN[@]}" "$ref"
    [ "$status" -eq 0 ] || fail "control: $ref does not verify against the golden identity: $output"
    refute_foreign_identities "$ref"
  done
}

@test "golden build verified the DHI base signature" {
  [ -n "${DHI_USERNAME:-}" ] || fail "DHI_USERNAME is not set in the environment"
  [ -n "${DHI_TOKEN:-}" ] || fail "DHI_TOKEN is not set in the environment"
  resolve_golden_run
  golden_cosign_args

  jobs="$BATS_TEST_TMPDIR/jobs.json"
  gh api -X GET "repos/$GITHUB_REPO/actions/runs/$GOLDEN_RUN_ID/jobs" -f per_page=100 >"$jobs" ||
    fail "cannot list the jobs of $GOLDEN_WORKFLOW run $GOLDEN_RUN_ID"

  # dhi.io serves signatures only to an authenticated client: a throwaway Docker config, token on stdin.
  export DOCKER_CONFIG="$BATS_TEST_TMPDIR/docker"
  (umask 077 && mkdir -p "$DOCKER_CONFIG")
  printf '%s' "$DHI_TOKEN" | crane auth login dhi.io -u "$DHI_USERNAME" --password-stdin >/dev/null 2>&1 ||
    fail "crane auth login dhi.io failed for DHI_USERNAME"
  dhi_key="$BATS_TEST_TMPDIR/dhi.pub"
  curl -sSfL "$DHI_PUBLIC_KEY_URL" -o "$dhi_key" || fail "cannot fetch the DHI public key $DHI_PUBLIC_KEY_URL"

  for name in "${GOLDEN_IMAGES[@]}"; do
    jq -e --arg image "$name" --arg step "$DHI_STEP" \
      'any(.jobs[]; (.name | contains($image)) and any(.steps[]?; .name == $step and .conclusion == "success"))' \
      "$jobs" >/dev/null ||
      fail "run $GOLDEN_RUN_ID has no job for $name whose step '$DHI_STEP' concluded success: $(
        jq -c '[.jobs[] | {name, steps: [.steps[]? | select(.name | test("DHI"; "i")) | {name, conclusion}]}]' "$jobs"
      )"

    ref="$GHCR_GOLDEN/$name@$(golden_ghcr_digest "$name")"
    provenance="$BATS_TEST_TMPDIR/provenance-$name.json"
    cosign verify-attestation "${GOLDEN_COSIGN[@]}" --type slsaprovenance1 "$ref" >"$provenance" 2>/dev/null ||
      fail "SLSA provenance of $ref not verified against $(golden_identity)"
    mapfile -t bases < <(attestation_statements "$provenance" | jq -r '[.[].predicate.buildDefinition.resolvedDependencies[]?
        | select(.uri | startswith("oci://dhi.io/")) | "\(.uri)|\(.digest.sha256 // "")"] | unique[]')
    [ "${#bases[@]}" -eq 1 ] ||
      fail "SLSA provenance of $ref records ${#bases[@]} dhi.io base(s), expected exactly one: ${bases[*]}"
    IFS='|' read -r base_uri base_hex <<<"${bases[0]}"
    [[ "$base_hex" =~ ^[0-9a-f]{64}$ ]] || fail "dhi.io base $base_uri has no sha256 digest in the provenance of $ref"
    base_repo="${base_uri#oci://}"
    base_repo="${base_repo%%@*}"
    if [[ "${base_repo##*/}" == *:* ]]; then
      base_repo="${base_repo%:*}"
    fi

    dockerfile_from="$(git -C "$REPO_ROOT" show "$GOLDEN_SHA:images/golden/$name/Dockerfile" |
      awk 'toupper($1) == "FROM" { for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; exit } }')"
    [[ "$dockerfile_from" == dhi.io/*@sha256:* ]] ||
      fail "images/golden/$name/Dockerfile at ${GOLDEN_SHA:0:12} is not FROM a digest-pinned dhi.io image: '$dockerfile_from'"
    [ "${dockerfile_from##*@sha256:}" = "$base_hex" ] ||
      fail "provenance base digest $base_hex differs from the pinned FROM $dockerfile_from"

    run cosign verify --key "$dhi_key" --experimental-oci11 "$base_repo@sha256:$base_hex"
    [ "$status" -eq 0 ] ||
      fail "$base_repo@sha256:$base_hex does not verify against the DHI public key: $(tail -n 5 <<<"$output")"
    run cosign verify --key "$dhi_key" --experimental-oci11 "$ref"
    [ "$status" -ne 0 ] || fail "control: $ref verifies against the DHI key; the DHI key check proves nothing"
  done
}
