#!/usr/bin/env bats
# Golden-path application contract, read statically: an app's workflow is one `uses:` line to the
# platform's build-image.yml and its Dockerfile only needs FROM a golden image; the platform owns the
# signing, attestations and the VEX-aware Trivy scan.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
BUILD_WORKFLOW=.github/workflows/build-image.yml
CATALOG=images/catalog.yaml
# app|golden base it runs on
APPS=(
  "dt-bridge|python"
  "hello-java|java"
)
LOCAL_BUILD_USES=./.github/workflows/build-image.yml
REMOTE_BUILD_USES='^naqa92-portfolio-projects/harborlab/\.github/workflows/build-image\.yml@[0-9a-f]{40}$'
GOLDEN_REFERENCE='^(ghcr\.io/naqa92-portfolio-projects/harborlab/golden|harbor\.127\.0\.0\.1\.nip\.io/golden)/([a-z0-9-]+)(:[^@/]+)?@(sha256:[0-9a-f]{64})$'
# The only permissions a caller grants, the ones build-image.yml needs to push, sign and attest.
ALLOWED_PERMISSIONS='{"contents": "read", "packages": "write", "id-token": "write"}'
SECURITY_TOOLING='cosign|syft|trivy|grype|notation|sigstore|attest|sbom|provenance'
CERTIFICATE_PATTERN='\.(crt|pem|cer|der|p12|pfx|jks)([[:space:]"]|$)|ca-certificates|cacerts|/certs?(/|[[:space:]"]|$)'
CA_INSTALL_PATTERN='update-ca-certificates|update-ca-trust|keytool[^|;&]*-import|trust anchor'

fail() {
  echo "$*" >&2
  return 1
}

# Dockerfile instructions one per line: continuations joined, comments and blank lines dropped.
instructions() {
  awk '
    /^[[:space:]]*#/ { next }
    { sub(/\r$/, "") }
    /\\[[:space:]]*$/ { sub(/\\[[:space:]]*$/, ""); line = line $0 " "; next }
    { line = line $0; if (line ~ /[^[:space:]]/) print line; line = "" }
  ' "$1"
}

@test "app workflows are a single uses line to build-image.yml" {
  for entry in "${APPS[@]}"; do
    app="${entry%%|*}"
    workflow=".github/workflows/$app.yml"
    [ -f "$REPO_ROOT/$workflow" ] || fail "$workflow does not exist"
    wf="$(yq -o=json '.' "$REPO_ROOT/$workflow")" || fail "$workflow is not valid YAML"

    jq -e '(.on.push.branches // []) | index("main") != null' <<<"$wf" >/dev/null ||
      fail "$workflow does not build on pushes to main: $(jq -c '.on' <<<"$wf")"
    jq -e --arg p "apps/$app/**" '(.on.push.paths // []) | index($p) != null' <<<"$wf" >/dev/null ||
      fail "$workflow push.paths does not list apps/$app/**: $(jq -c '.on.push.paths' <<<"$wf")"

    jq -e '.jobs | type == "object" and length == 1' <<<"$wf" >/dev/null ||
      fail "$workflow must have exactly one job, has: $(jq -c '.jobs | keys? // .' <<<"$wf")"
    job="$(jq -c '.jobs | to_entries[0].value' <<<"$wf")"
    uses="$(jq -r '.uses // ""' <<<"$job")"
    [ "$uses" = "$LOCAL_BUILD_USES" ] || [[ "$uses" =~ $REMOTE_BUILD_USES ]] ||
      fail "$workflow job does not call build-image.yml: uses '$uses'"
    extra_keys="$(jq -r 'keys - ["name", "uses", "with", "permissions"] | join(", ")' <<<"$job")"
    [ -z "$extra_keys" ] || fail "$workflow job sets more than the call and its inputs: $extra_keys"
    uses_lines="$(grep -cE '^[[:space:]]*(-[[:space:]]+)?uses:' "$REPO_ROOT/$workflow" || true)"
    [ "$uses_lines" -eq 1 ] || fail "$workflow has $uses_lines uses: lines, expected one"

    jq -e --arg app "apps/$app" '(.with // {}) == {image: $app, context: $app}' <<<"$job" >/dev/null ||
      fail "$workflow inputs must be exactly image and context apps/$app: $(jq -c '.with' <<<"$job")"

    for scope in '.permissions' '.jobs | to_entries[0].value.permissions'; do
      jq -e --argjson allowed "$ALLOWED_PERMISSIONS" "($scope) as \$p | \$p == null or
          (\$p | type == \"object\" and all(to_entries[]; \$allowed[.key] == .value))" <<<"$wf" >/dev/null ||
        fail "$workflow grants permissions beyond what the build-image.yml call needs: $(jq -c "$scope" <<<"$wf")"
    done

    # Values only: comments are not configuration.
    found="$(jq -r '.. | strings, (objects | keys[])' <<<"$wf" | grep -oiE "$SECURITY_TOOLING" | sort -u | tr '\n' ' ' || true)"
    [ -z "$found" ] || fail "$workflow configures security tooling itself: $found"
  done
}

@test "app Dockerfiles only need FROM a golden image" {
  for entry in "${APPS[@]}"; do
    app="${entry%%|*}"
    golden="${entry#*|}"
    dockerfile="apps/$app/Dockerfile"
    [ -f "$REPO_ROOT/$dockerfile" ] || fail "$dockerfile does not exist"
    instructions "$REPO_ROOT/$dockerfile" >"$BATS_TEST_TMPDIR/$app.instructions"

    stages=" "
    final_from=""
    while read -r from alias; do
      if [[ "$stages" != *" $from "* ]]; then
        [[ "$from" =~ $GOLDEN_REFERENCE ]] || fail "$dockerfile: FROM $from is not a digest-pinned golden image"
        name="${BASH_REMATCH[2]}"
        digest="${BASH_REMATCH[4]}"
        status="$(yq -r ".images[] | select(.name == \"$name\" and .digest == \"$digest\") | .status" "$REPO_ROOT/$CATALOG" | sort -u)"
        [ "$status" = supported ] ||
          fail "$dockerfile: FROM $from is not a supported entry of $CATALOG (status: '${status:-absent}')"
      fi
      [ -z "$alias" ] || stages+="$alias "
      final_from="$from"
    done < <(awk 'toupper($1) == "FROM" {
        image = ""; alias = ""
        for (i = 2; i <= NF; i++) {
          if (image == "" && $i !~ /^--/) image = $i
          else if (image != "" && toupper($i) == "AS" && i < NF) alias = $(i + 1)
        }
        print image, alias
      }' "$BATS_TEST_TMPDIR/$app.instructions")
    [ -n "$final_from" ] || fail "$dockerfile has no FROM"
    [[ "$final_from" =~ $GOLDEN_REFERENCE ]] ||
      fail "$dockerfile: the final stage must be FROM a golden image directly, not '$final_from'"
    [ "${BASH_REMATCH[2]}" = "$golden" ] ||
      fail "$dockerfile: the final stage runs on golden ${BASH_REMATCH[2]}, expected golden $golden"

    copied="$(grep -iE '^[[:space:]]*(COPY|ADD)[[:space:]]' "$BATS_TEST_TMPDIR/$app.instructions" |
      grep -iE "$CERTIFICATE_PATTERN" || true)"
    [ -z "$copied" ] || fail "$dockerfile copies a certificate into the image: $copied"
    installed="$(grep -iE '^[[:space:]]*RUN[[:space:]]' "$BATS_TEST_TMPDIR/$app.instructions" |
      grep -iE "$CA_INSTALL_PATTERN" || true)"
    [ -z "$installed" ] || fail "$dockerfile installs a CA into the image trust store: $installed"
    tooling="$(grep -iE '^[[:space:]]*(RUN|ENTRYPOINT|CMD)[[:space:]]' "$BATS_TEST_TMPDIR/$app.instructions" |
      grep -iwE 'cosign|syft|trivy|grype|notation' || true)"
    [ -z "$tooling" ] || fail "$dockerfile runs signing or scanning tooling itself: $tooling"

    last_from="$(grep -inE '^[[:space:]]*FROM[[:space:]]' "$BATS_TEST_TMPDIR/$app.instructions" | tail -1 | cut -d: -f1)"
    while IFS= read -r user_line; do
      [ -n "$user_line" ] || continue
      [ "${user_line%%:*}" -gt "$last_from" ] || continue
      user="$(awk '{ print $2 }' <<<"${user_line#*:}")"
      user="${user%%:*}"
      [ "$user" != root ] && [ "$user" != 0 ] || fail "$dockerfile runs its final stage as root: ${user_line#*:}"
    done < <(grep -inE '^[[:space:]]*USER[[:space:]]' "$BATS_TEST_TMPDIR/$app.instructions" || true)
  done
}

@test "build-image.yml scans with Trivy using VEX from OCI" {
  [ -f "$REPO_ROOT/$BUILD_WORKFLOW" ] || fail "$BUILD_WORKFLOW does not exist"
  steps="$(yq -o=json '[.jobs[].steps[]?]' "$REPO_ROOT/$BUILD_WORKFLOW")" || fail "$BUILD_WORKFLOW is not valid YAML"

  scan="$(jq -r 'to_entries | map(select((.value.run // "") | test("trivy") and test("--vex[= ]oci"))) | .[0].key // empty' <<<"$steps")"
  [ -n "$scan" ] || fail "$BUILD_WORKFLOW has no step running trivy with --vex oci"
  jq -e --argjson i "$scan" '.[$i].name | type == "string" and length > 0' <<<"$steps" >/dev/null ||
    fail "the Trivy step of $BUILD_WORKFLOW has no name (the live test finds it by name)"
  jq -e --argjson i "$scan" '.[$i]["continue-on-error"] != true' <<<"$steps" >/dev/null ||
    fail "the Trivy step of $BUILD_WORKFLOW does not block the build (continue-on-error: true)"
  jq -e --argjson i "$scan" '.[$i].if == null' <<<"$steps" >/dev/null ||
    fail "the Trivy step of $BUILD_WORKFLOW is conditional: $(jq -r --argjson i "$scan" '.[$i].if' <<<"$steps")"

  sign="$(jq -r 'to_entries | map(select((.value.run // "") | test("cosign sign"))) | .[0].key // empty' <<<"$steps")"
  [ -n "$sign" ] || fail "$BUILD_WORKFLOW has no step running cosign sign"
  [ "$scan" -lt "$sign" ] || fail "$BUILD_WORKFLOW signs the image before the Trivy scan"
}
