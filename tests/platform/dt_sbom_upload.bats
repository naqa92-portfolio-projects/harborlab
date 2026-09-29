#!/usr/bin/env bats
# Harbor replication → webhook → dt-bridge → Dependency-Track, live on the kind platform: the SBOM stored in
# Dependency-Track is the CycloneDX attestation signed at build time, in a project named after the image
# with its tag as version.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
load ../supply-chain/golden
load ../supply-chain/apps
load dt

UPLOAD_TIMEOUT_SECONDS=300
# Harbor and Dependency-Track run on the host clock; this absorbs sub-second rounding only.
CLOCK_MARGIN_MS=2000

setup_file() {
  dt_setup_file
}

setup() {
  dt_setup
}

# The replication of image $1 (Harbor `<project>/<repository>`, tag $2) started at $4 (epoch ms) leads,
# within UPLOAD_TIMEOUT_SECONDS of its end, to a BOM import into the DT project $1 version $2 whose
# component purls are those of the verified CycloneDX attestation (cosign output in file $3).
assert_attested_sbom_in_dependency_track() {
  local image="$1" tag="$2" attestation="$3" started_ms="$4" deadline uuid imported_ms diagnosis
  attestation_statements "$attestation" | jq '[.[] | .predicate]' >"$BATS_TEST_TMPDIR/attested-sboms.json"
  jq -e 'length == 1' "$BATS_TEST_TMPDIR/attested-sboms.json" >/dev/null ||
    fail "expected one CycloneDX attestation on $image:$tag, found $(jq length "$BATS_TEST_TMPDIR/attested-sboms.json")"
  jq '.[0]' "$BATS_TEST_TMPDIR/attested-sboms.json" | cyclonedx_purls >"$BATS_TEST_TMPDIR/attested-purls.txt"
  [ -s "$BATS_TEST_TMPDIR/attested-purls.txt" ] || fail "the CycloneDX attestation of $image:$tag holds no purl"

  deadline=$((SECONDS + UPLOAD_TIMEOUT_SECONDS))
  while :; do
    uuid="$(dt_project_uuid "$image" "$tag")" || return 1
    if [ -z "$uuid" ]; then
      diagnosis="no Dependency-Track project '$image' version '$tag'"
    else
      imported_ms="$(dt_last_bom_import_ms "$uuid")" || return 1
      if [ "${imported_ms%.*}" -lt $((started_ms - CLOCK_MARGIN_MS)) ]; then
        diagnosis="project '$image' version '$tag' has no BOM import since the replication (last import: $imported_ms ms, replication start: $started_ms ms)"
      else
        dt_components "$uuid" "$BATS_TEST_TMPDIR/dt-components.json" || return 1
        jq -r "$PURL_JQ"' [.[] | .purl // empty | purl_norm] | unique[]' "$BATS_TEST_TMPDIR/dt-components.json" \
          >"$BATS_TEST_TMPDIR/dt-purls.txt"
        if cmp -s "$BATS_TEST_TMPDIR/attested-purls.txt" "$BATS_TEST_TMPDIR/dt-purls.txt"; then
          return 0
        fi
        diagnosis="component purls of project '$image' version '$tag' differ from the attested SBOM: $(
          comm -23 "$BATS_TEST_TMPDIR/attested-purls.txt" "$BATS_TEST_TMPDIR/dt-purls.txt" | wc -l
        ) attested purl(s) missing in DT (e.g. $(comm -23 "$BATS_TEST_TMPDIR/attested-purls.txt" "$BATS_TEST_TMPDIR/dt-purls.txt" | head -n 3 | tr '\n' ' ')), $(
          comm -13 "$BATS_TEST_TMPDIR/attested-purls.txt" "$BATS_TEST_TMPDIR/dt-purls.txt" | wc -l
        ) DT purl(s) absent from the attestation (e.g. $(comm -13 "$BATS_TEST_TMPDIR/attested-purls.txt" "$BATS_TEST_TMPDIR/dt-purls.txt" | head -n 3 | tr '\n' ' '))"
      fi
    fi
    [ "$SECONDS" -lt "$deadline" ] || fail "${UPLOAD_TIMEOUT_SECONDS}s after the replication: $diagnosis"
    sleep 10
  done
}

# No DT project version of image $1 is a referrers fallback tag (`sha256-<hex>`): only image tags are projects.
refute_referrer_tag_projects() {
  local image="$1"
  dt_get /v1/project -G --data-urlencode "name=$image" --data-urlencode pageSize=500 || return 1
  [ "$HTTP_CODE" = 200 ] || fail "cannot list Dependency-Track projects named $image (HTTP $HTTP_CODE)"
  referrer_versions="$(jq -r --arg n "$image" '.[] | select(.name == $n) | .version // "" | select(startswith("sha256-"))' "$HTTP_BODY")"
  [ -z "$referrer_versions" ] ||
    fail "Dependency-Track holds projects '$image' for referrers fallback tags, not images: $referrer_versions"
}

@test "replicated app image SBOM lands in Dependency-Track as attested" {
  app=hello-java
  resolve_app_run "$app"
  digest="$(app_ghcr_digest "$app")"
  tag="sha-$APP_SHA"

  started_ms="$(date +%s%3N)"
  replicate "$APPS_REPLICATION"
  code="$(curl -sS --cacert "$PLATFORM_CA" -o /dev/null -w '%{http_code}' \
    "https://$HARBOR_HOST/api/v2.0/projects/$APPS_PROJECT/repositories/$app/artifacts/$tag")"
  [ "$code" = 200 ] || fail "$APPS_PROJECT/$app:$tag not in Harbor after replication $APPS_REPLICATION ($REPLICATION_STATUS, HTTP $code)"

  app_cosign_args
  attestation="$BATS_TEST_TMPDIR/attestation-cyclonedx.json"
  cosign verify-attestation "${APP_COSIGN[@]}" --registry-cacert "$PLATFORM_CA" --type cyclonedx \
    "$HARBOR_HOST/$APPS_PROJECT/$app@$digest" >"$attestation" 2>"$BATS_TEST_TMPDIR/cosign.err" ||
    fail "CycloneDX attestation of $HARBOR_HOST/$APPS_PROJECT/$app@$digest not verified: $(tail -n 5 "$BATS_TEST_TMPDIR/cosign.err")"

  assert_attested_sbom_in_dependency_track "$APPS_PROJECT/$app" "$tag" "$attestation" "$started_ms"
  refute_referrer_tag_projects "$APPS_PROJECT/$app"
}

@test "replicated golden image SBOM lands in Dependency-Track as attested" {
  name=python
  resolve_golden_run
  digest="$(golden_ghcr_digest "$name")"
  tag="sha-$GOLDEN_SHA"

  started_ms="$(date +%s%3N)"
  replicate "$GOLDEN_REPLICATION"
  code="$(curl -sS --cacert "$PLATFORM_CA" -o /dev/null -w '%{http_code}' \
    "https://$HARBOR_HOST/api/v2.0/projects/$GOLDEN_PROJECT/repositories/$name/artifacts/$tag")"
  [ "$code" = 200 ] || fail "$GOLDEN_PROJECT/$name:$tag not in Harbor after replication $GOLDEN_REPLICATION ($REPLICATION_STATUS, HTTP $code)"

  golden_cosign_args
  attestation="$BATS_TEST_TMPDIR/attestation-cyclonedx.json"
  cosign verify-attestation "${GOLDEN_COSIGN[@]}" --registry-cacert "$PLATFORM_CA" --type cyclonedx \
    "$HARBOR_HOST/$GOLDEN_PROJECT/$name@$digest" >"$attestation" 2>"$BATS_TEST_TMPDIR/cosign.err" ||
    fail "CycloneDX attestation of $HARBOR_HOST/$GOLDEN_PROJECT/$name@$digest not verified: $(tail -n 5 "$BATS_TEST_TMPDIR/cosign.err")"

  assert_attested_sbom_in_dependency_track "$GOLDEN_PROJECT/$name" "$tag" "$attestation" "$started_ms"
  refute_referrer_tag_projects "$GOLDEN_PROJECT/$name"
}
