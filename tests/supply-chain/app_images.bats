#!/usr/bin/env bats
# Golden-path app images on GHCR, live: built by their one-line workflow through the platform's
# build-image.yml, which signs, attests and runs the VEX-aware Trivy scan for them.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
load golden
load apps

@test "app images are signed and attested by build-image.yml" {
  for app in "${APP_NAMES[@]}"; do
    resolve_app_run "$app"
    digest="$(app_ghcr_digest "$app")"
    ref="$GHCR_APPS/$app@$digest"
    verify_app_signed_and_attested "$app" "$ref"
    refute_app_foreign_identities "$app" "$ref"
  done
}

@test "app build ran the VEX-aware Trivy scan" {
  for app in "${APP_NAMES[@]}"; do
    resolve_app_run "$app"

    # The scan step is the build-image.yml step running `trivy` with `--vex oci`, at the built commit.
    step="$(git -C "$REPO_ROOT" show "$APP_SHA:$BUILD_WORKFLOW_FILE" |
      yq -o=json '[.jobs[].steps[]? | select((.run // "") | test("trivy") and test("--vex[= ]oci")) | .name] | .[0] // ""' |
      jq -r .)"
    [ -n "$step" ] && [ "$step" != null ] ||
      fail "$BUILD_WORKFLOW_FILE at ${APP_SHA:0:12} has no named step running trivy with --vex oci"

    jobs="$BATS_TEST_TMPDIR/jobs-$app.json"
    gh api -X GET "repos/$GITHUB_REPO/actions/runs/$APP_RUN_ID/jobs" -f per_page=100 >"$jobs" ||
      fail "cannot list the jobs of $app.yml run $APP_RUN_ID"
    jq -e --arg step "$step" 'any(.jobs[]; any(.steps[]?; .name == $step and .conclusion == "success"))' \
      "$jobs" >/dev/null ||
      fail "$app.yml run $APP_RUN_ID has no step '$step' concluded success: $(
        jq -c '[.jobs[] | {name, steps: [.steps[]? | select(.name | test("trivy"; "i")) | {name, conclusion}]}]' "$jobs"
      )"
  done
}
