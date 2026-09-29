#!/usr/bin/env bats
# What build-image.yml signs and records, read statically from the workflow: only digests it built,
# a base taken from BuildKit's own record of the build, and the DHI key pinned in the repository.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
BUILD_WORKFLOW=.github/workflows/build-image.yml
GOLDEN_WORKFLOW=.github/workflows/golden.yml
DT_BRIDGE_DOCKERFILE=apps/dt-bridge/Dockerfile
# SHA-256 of the DER SubjectPublicKeyInfo of the DHI signing key (https://dhi.io/keyring/latest.pub).
DHI_SIGNER_SPKI_SHA256=118ba556dd52f4aec67018efd316c285c783cd3e54cc0f4527605715c643887c

fail() {
  echo "$*" >&2
  return 1
}

setup() {
  WORKFLOW_JSON="$(yq -o=json '.' "$REPO_ROOT/$BUILD_WORKFLOW")" || fail "$BUILD_WORKFLOW is not valid YAML"
}

# Steps of the build job as JSON, each with its index and the text of its env, with, if and run.
steps_json() {
  jq '[.jobs.build.steps | to_entries[] | .value + {
      index: .key,
      text: ((.value.env // {} | tostring) + "\n" + (.value.with // {} | tostring) + "\n"
        + (.value.if // "" | tostring) + "\n" + (.value.run // ""))
    }]' <<<"$WORKFLOW_JSON"
}

@test "build-image.yml signs and attests only the digest it built" {
  steps="$(steps_json)"
  build_id="$(jq -r '[.[] | select((.uses // "") | startswith("docker/build-push-action@"))][0].id // ""' <<<"$steps")"
  [ -n "$build_id" ] || fail "$BUILD_WORKFLOW has no docker/build-push-action step with an id"
  build_if="$(jq -r --arg b "$build_id" '.[] | select(.id == $b) | .if // ""' <<<"$steps")"

  signers="$(jq -c '.[] | select((.run // "") | test("cosign (sign|attest)"))' <<<"$steps")"
  [ -n "$signers" ] || fail "$BUILD_WORKFLOW has no step running cosign sign or cosign attest"
  while read -r step; do
    name="$(jq -r '.name // "step \(.index)"' <<<"$step")"
    sign_if="$(jq -r '.if // ""' <<<"$step")"
    # Skipped together with the build: the step runs only when the image was built here.
    if [ -n "$build_if" ] && [ "$sign_if" = "$build_if" ]; then continue; fi
    if grep -qF "steps.$build_id." <<<"$sign_if"; then continue; fi
    # Otherwise every step output it reads is the build step's, directly or through one step that only
    # reads the build step's outputs.
    for source in $(jq -r '.text | [scan("steps\\.([A-Za-z0-9_-]+)\\.outputs")[0]] | unique[]' <<<"$step"); do
      [ "$source" = "$build_id" ] && continue
      upstream="$(jq -r --arg s "$source" '.[] | select(.id == $s)
        | .text | [scan("steps\\.([A-Za-z0-9_-]+)\\.outputs")[0]] | unique | join(" ")' <<<"$steps")"
      [ "$upstream" = "$build_id" ] ||
        fail "'$name' signs a digest from step '$source', which reads '${upstream:-no step output}' besides the build step '$build_id': a pre-existing tag can be signed without being built or verified"
    done
  done <<<"$signers"
}

@test "base recorded in the image labels and SLSA provenance comes from BuildKit, not the Dockerfile text" {
  steps="$(steps_json)"
  build_id="$(jq -r '[.[] | select((.uses // "") | startswith("docker/build-push-action@"))][0].id // ""' <<<"$steps")"
  [ -n "$build_id" ] || fail "$BUILD_WORKFLOW has no docker/build-push-action step with an id"
  # Steps that read the Dockerfile as text: a `# syntax=` frontend or a heredoc line starting with FROM
  # makes their answer differ from the base BuildKit actually used.
  parsers="$(jq -r '.[] | select(.id != null and ((.run // "") | test("Dockerfile") and test("\\b(awk|sed|grep|cut|read)\\b")))
    | .id' <<<"$steps")"

  labels="$(jq -r --arg b "$build_id" '.[] | select(.id == $b) | .with.labels // ""' <<<"$steps")"
  for parser in $parsers; do
    ! grep -qF "steps.$parser.outputs" <<<"$labels" ||
      fail "the image labels of step '$build_id' record step '$parser' outputs, parsed from the Dockerfile text: $(grep -F "steps.$parser.outputs" <<<"$labels")"
  done

  provenance="$(jq -c '[.[] | select((.run // "") | test("resolvedDependencies"))][0] // empty' <<<"$steps")"
  [ -n "$provenance" ] || fail "$BUILD_WORKFLOW writes no SLSA provenance (no step builds resolvedDependencies)"
  sources="$(jq -r '.text | [scan("steps\\.([A-Za-z0-9_-]+)\\.outputs")[0]] | unique[]' <<<"$provenance")"
  for parser in $parsers; do
    ! grep -qx "$parser" <<<"$sources" ||
      fail "the SLSA provenance records the base from step '$parser', which parses the Dockerfile text"
  done
  # The base comes from the build's own record: build-push-action's metadata output, or a step reading
  # it (buildx metadata, imagetools inspect, buildx history).
  from_buildkit=false
  for source in $sources; do
    if [ "$source" = "$build_id" ] && jq -e '.text | test("outputs\\.metadata")' <<<"$provenance" >/dev/null; then
      from_buildkit=true
    elif jq -e --arg s "$source" --arg b "$build_id" '.[] | select(.id == $s)
        | .text | test("steps\\." + $b + "\\.outputs\\.metadata|imagetools inspect|buildx history")' <<<"$steps" >/dev/null; then
      from_buildkit=true
    fi
  done
  [ "$from_buildkit" = true ] ||
    fail "the SLSA provenance base does not come from BuildKit's record of the build (sources: ${sources:-none})"
}

@test "DHI base signature is verified against the DHI key pinned in the repository" {
  ! grep -q 'dhi\.io/keyring' "$REPO_ROOT/$BUILD_WORKFLOW" ||
    fail "$BUILD_WORKFLOW still fetches the DHI key at build time: $(grep -n 'dhi\.io/keyring' "$REPO_ROOT/$BUILD_WORKFLOW")"
  step="$(steps_json | jq -c '[.[] | select((.run // "") | test("cosign verify[^\n]*--key"))][0] // empty')"
  [ -n "$step" ] || fail "$BUILD_WORKFLOW has no step running cosign verify --key"
  key="$(jq -r '.run | capture("--key[ =](?<k>\"?[^ \"]+\"?)").k | gsub("\""; "")' <<<"$step")"
  if [[ "$key" =~ ^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$ ]]; then
    var="${BASH_REMATCH[1]}"
    key="$(jq -r --arg v "$var" --argjson step "$step" '$step.env[$v] // .jobs.build.env[$v] // .env[$v] // ""' <<<"$WORKFLOW_JSON")"
  fi
  [ -n "$key" ] || fail "cannot resolve the --key argument of the DHI verification step"
  [[ "$key" != *://* ]] || fail "the DHI key is read from $key, not from a file pinned in the repository"
  key="${key#./}"
  git -C "$REPO_ROOT" ls-files --error-unmatch "$key" >/dev/null 2>&1 ||
    fail "the DHI key $key is not a file tracked in the repository"
  fingerprint="$(openssl pkey -pubin -in "$REPO_ROOT/$key" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
  [ "$fingerprint" = "$DHI_SIGNER_SPKI_SHA256" ] ||
    fail "$key is not the DHI signing key (SPKI SHA-256 ${fingerprint:-unreadable}, expected $DHI_SIGNER_SPKI_SHA256)"
}

@test "dt-bridge image installs uv with hash pinning or from a digest-pinned image" {
  dockerfile="$REPO_ROOT/$DT_BRIDGE_DOCKERFILE"
  [ -f "$dockerfile" ] || fail "$DT_BRIDGE_DOCKERFILE does not exist"
  # A pip install of uv must carry its hashes; a copy of uv must come from an image pinned by digest.
  unpinned="$(grep -nE '^RUN .*pip[^ ]*"?,? *"?install' "$dockerfile" | grep -E 'uv' | grep -vE -- '--hash=sha256:|--require-hashes' || true)"
  [ -z "$unpinned" ] || fail "$DT_BRIDGE_DOCKERFILE installs uv from PyPI without hashes: $unpinned"
  grep -qE '(--hash=sha256:[0-9a-f]{64}|--require-hashes)' "$dockerfile" ||
    grep -qE '^COPY --from=[^ ]*uv[^ ]*@sha256:[0-9a-f]{64}' "$dockerfile" ||
    fail "$DT_BRIDGE_DOCKERFILE installs uv neither hash-pinned nor from a digest-pinned image"
}

@test "golden builds on main keep images/catalog.yaml in step" {
  run yq -o=json '.' "$REPO_ROOT/$GOLDEN_WORKFLOW"
  [ "$status" -eq 0 ] || fail "$GOLDEN_WORKFLOW is not valid YAML"
  golden="$output"
  builds="$(jq -r '.jobs | to_entries[] | select((.value.uses // "") | test("build-image\\.yml")) | .key' <<<"$golden")"
  [ -n "$builds" ] || fail "$GOLDEN_WORKFLOW calls build-image.yml in no job"
  # A job after the builds turns their published digests into a catalog change.
  updater="$(jq -r --arg builds "$builds" '($builds | split("\n")) as $b | .jobs | to_entries[]
    | select((.value.needs // [] | if type == "string" then [.] else . end) as $n | any($b[]; . as $x | $n | index($x)))
    | select(.value | tostring | test("needs\\.[A-Za-z0-9_-]+\\.outputs\\.digest"))
    | select(.value | tostring | test("images/catalog\\.yaml|catalog\\.sh|catalog:"))
    | .key' <<<"$golden")"
  [ -n "$updater" ] ||
    fail "$GOLDEN_WORKFLOW has no job that needs the golden builds, reads their digest outputs and updates images/catalog.yaml"
}
