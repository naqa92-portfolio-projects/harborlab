#!/usr/bin/env bats
# Admission policies: their CI wiring, the Kyverno CEL policy set covering each deny/warn case, and the
# E2E params, which may only add fixture entries to the production params.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
POLICY_WORKFLOW=.github/workflows/policies.yml
KYVERNO_SUITES=tests/kyverno
CHAINSAW_WORKLOAD=tests/chainsaw/workload
PROD_GOLDEN_PARAMS=policies/params/golden-images.yaml
PROD_REGISTRY_PARAMS=policies/params/registries.yaml
E2E_GOLDEN_PARAMS=tests/chainsaw/params/golden-images.yaml
E2E_REGISTRY_PARAMS=tests/chainsaw/params/registries.yaml
CATALOG=images/catalog.yaml
FIXTURE_SOURCES=tests/fixtures/images
FIXTURES_PREFIX=ghcr.io/naqa92-portfolio-projects/harborlab/fixtures/
HARBOR_WORKLOAD_PREFIXES=$'harbor.127.0.0.1.nip.io/apps/\nharbor.127.0.0.1.nip.io/golden/'
FIXTURE_PIN=images/demo-fixtures.yaml
FIXTURE_TAG_HELPER=tests/fixtures/fixture-tag.sh

# "<case>|<policy name>" per deny/warn case of criteria 9-10; PSS restricted is native Pod Security
# Admission, which `kyverno test` does not evaluate.
CASES=(
  "unsigned|workload-image-signature"
  "foreign-signer|workload-image-signature"
  "non-harbor-registry|workload-registry"
  "eol-base|workload-golden-base"
  "unknown-base|workload-golden-base"
  "no-sbom|workload-image-signature"
  "missing-labels|workload-image-labels"
  "deprecated-base|workload-golden-base-deprecated"
  "pss-restricted|"
)

# "<file under policies/>|<kind>|<metadata.name>|<validationActions the policy must hold>|<actions it must not hold>"
POLICIES=(
  "workload/image-signature.yaml|ImageValidatingPolicy|workload-image-signature|Deny|"
  "workload/golden-base.yaml|ImageValidatingPolicy|workload-golden-base|Deny|"
  "workload/golden-base-deprecated.yaml|ImageValidatingPolicy|workload-golden-base-deprecated|Warn Audit|Deny"
  "workload/image-labels.yaml|ImageValidatingPolicy|workload-image-labels|Deny|"
  "workload/registry.yaml|ValidatingPolicy|workload-registry|Deny|"
  "workload/pod-security.yaml|MutatingPolicy|workload-pod-security||"
  "platform/registry-allow-list.yaml|ValidatingPolicy|platform-registry-allow-list|Audit|Deny"
  "platform/vendor-signatures.yaml|ImageValidatingPolicy|platform-vendor-signatures|Audit|Deny"
)

fail() {
  echo "$*" >&2
  return 1
}

# Scripts (`run`) and actions (`uses`) of the steps CI does not allow to fail, one job per JSON line.
blocking_jobs() {
  yq -o=json -I=0 '.jobs | to_entries[] | select(.value["continue-on-error"] != true)
    | {"name": .key, "text": ([.value.steps[]? | select(.["continue-on-error"] != true)
        | ((.run // "") + "\n" + (.uses // ""))] | join("\n"))}' "$REPO_ROOT/$POLICY_WORKFLOW"
}

# Entries of a newline-separated ConfigMap list value, sorted, one per line.
list_value() {
  yq ".data.$2 // \"\"" "$1" | sed '/^[[:space:]]*$/d' | sort
}

configmap_json() {
  yq -o=json -I=0 '.' "$1"
}

digest_key() {
  echo "sha256.${1#sha256:}"
}

# Digest of the first FROM of a fixture Dockerfile.
fixture_base_digest() {
  local from
  from="$(awk 'toupper($1) == "FROM" { print $2; exit }' "$REPO_ROOT/$FIXTURE_SOURCES/$1/Dockerfile")"
  [[ "$from" =~ @(sha256:[0-9a-f]{64})$ ]] || {
    fail "$FIXTURE_SOURCES/$1/Dockerfile: first FROM is not pinned by digest: $from"
    return 1
  }
  echo "${BASH_REMATCH[1]}"
}

# "<policy name>|<suite file>" per kyverno test suite. A suite loads exactly one policy: the kyverno CLI
# deadlocks when two ImageValidatingPolicies evaluate the same resource.
suite_policies() {
  local suite count policy_file
  while IFS= read -r -d '' suite; do
    count="$(yq '.policies | length' "$suite")" || { fail "${suite#"$REPO_ROOT/"} is not valid YAML"; return 1; }
    [ "$count" -eq 1 ] || { fail "${suite#"$REPO_ROOT/"} loads $count policies instead of one"; return 1; }
    policy_file="$(dirname "$suite")/$(yq '.policies[0]' "$suite")"
    [ -f "$policy_file" ] || { fail "${suite#"$REPO_ROOT/"} loads a missing policy file: $policy_file"; return 1; }
    echo "$(yq '.metadata.name' "$policy_file")|${suite#"$REPO_ROOT/"}"
  done < <(find "$REPO_ROOT/$KYVERNO_SUITES" -name kyverno-test.yaml -print0 | sort -z)
}

version_at_least() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]
}

@test "policy workflow runs kyverno test and Chainsaw on PRs touching policies" {
  [ -f "$REPO_ROOT/$POLICY_WORKFLOW" ] || fail "$POLICY_WORKFLOW does not exist"
  on="$(yq -o=json '.on' "$REPO_ROOT/$POLICY_WORKFLOW")" || fail "$POLICY_WORKFLOW is not valid YAML"

  jq -e 'if type == "object" then has("pull_request")
      elif type == "array" then index("pull_request") != null
      else . == "pull_request" end' <<<"$on" >/dev/null || fail "$POLICY_WORKFLOW does not trigger on pull_request"
  pr="$(jq -c 'if type == "object" then (.pull_request // {}) else {} end' <<<"$on")"
  jq -e '(has("branches") or has("branches-ignore")) | not' <<<"$pr" >/dev/null ||
    fail "$POLICY_WORKFLOW filters pull_request by branch: $pr"
  jq -e '(has("paths") | not) or (.paths | index("policies/**") != null)' <<<"$pr" >/dev/null ||
    fail "$POLICY_WORKFLOW pull_request.paths does not cover policies/**: $pr"
  jq -e '(.["paths-ignore"] // []) | map(select(startswith("policies"))) | length == 0' <<<"$pr" >/dev/null ||
    fail "$POLICY_WORKFLOW ignores changes under policies/: $pr"

  jobs="$(blocking_jobs)" || fail "cannot read the jobs of $POLICY_WORKFLOW"
  jq -e 'select(.text | test("tests/kyverno/run\\.sh")) | .name' <<<"$jobs" >/dev/null ||
    fail "no blocking job of $POLICY_WORKFLOW runs tests/kyverno/run.sh (kyverno test --registry on tests/kyverno)"
  jq -e 'select((.text | test("kind create cluster")) or (.text | test("helm/kind-action@")))
      | select(.text | test("helm (upgrade --install|install)[^\n]*kyverno"))
      | select(.text | test("tests/chainsaw/params"))
      | select((.text | test("policies/workload")) and (.text | test("policies/platform")))
      | select(.text | test("chainsaw test[^\n]*tests/chainsaw"))
      | .name' <<<"$jobs" >/dev/null ||
    fail "no blocking job of $POLICY_WORKFLOW creates a kind cluster, installs Kyverno with Helm, applies policies/workload, policies/platform and tests/chainsaw/params, then runs chainsaw test on tests/chainsaw"

  command -v kyverno >/dev/null || fail "kyverno CLI is not on the devbox PATH"
  command -v chainsaw >/dev/null || fail "chainsaw is not on the devbox PATH"
  version="$(kyverno version 2>/dev/null | awk '/^Version:/ { sub(/^v/, "", $2); print $2 }')"
  version_at_least "$version" 1.19 || fail "kyverno CLI $version is older than 1.19"
}

@test "every deny and warn case of criteria 9-10 has a kyverno test and a Chainsaw case" {
  suites="$(suite_policies)" || return 1
  for entry in "${POLICIES[@]}"; do
    IFS='|' read -r _ _ name _ <<<"$entry"
    count="$(grep -c "^$name|" <<<"$suites" || true)"
    [ "$count" -eq 1 ] || fail "$count kyverno test suites under $KYVERNO_SUITES load $name, expected one"
  done
  for case in "${CASES[@]}"; do
    IFS='|' read -r name policy <<<"$case"
    [ -f "$REPO_ROOT/$CHAINSAW_WORKLOAD/$name/chainsaw-test.yaml" ] ||
      fail "no Chainsaw case $CHAINSAW_WORKLOAD/$name/chainsaw-test.yaml"
    [ -n "$policy" ] || continue
    suite="$(grep "^$policy|" <<<"$suites" | cut -d'|' -f2)"
    results="$(yq -o=json -I=0 '.results[]' "$REPO_ROOT/$suite")" || fail "$suite is not valid YAML"
    jq -e --arg policy "$policy" --arg resource "workload-test/$name" \
      'select(.policy == $policy and .result == "fail" and ((.resources // []) | index($resource) != null))' \
      <<<"$results" >/dev/null || fail "$suite expects no fail of $policy for $name"
  done

  # Kyverno CEL policy types only (Decision 6): no ClusterPolicy or Policy under policies/.
  while IFS= read -r -d '' file; do
    if yq -e 'select(.apiVersion != null and (.apiVersion | test("^policies[.]kyverno[.]io/") | not))' "$file" \
      >/dev/null 2>&1; then
      fail "${file#"$REPO_ROOT/"} holds a policy that is not a Kyverno CEL policy type"
    fi
  done < <(find "$REPO_ROOT/policies" -path "$REPO_ROOT/policies/params" -prune -o -type f -name '*.yaml' -print0)

  for entry in "${POLICIES[@]}"; do
    IFS='|' read -r file kind name required forbidden <<<"$entry"
    path="$REPO_ROOT/policies/$file"
    [ -f "$path" ] || fail "policies/$file does not exist"
    doc="$(yq -o=json -I=0 '.' "$path")" || fail "policies/$file is not valid YAML"
    jq -e --arg kind "$kind" --arg name "$name" \
      '.apiVersion == "policies.kyverno.io/v1" and .kind == $kind and .metadata.name == $name' <<<"$doc" >/dev/null ||
      fail "policies/$file is not the policies.kyverno.io/v1 $kind $name: $(jq -c '{apiVersion, kind, name: .metadata.name}' <<<"$doc")"
    for action in $required; do
      jq -e --arg a "$action" '(.spec.validationActions // []) | index($a) != null' <<<"$doc" >/dev/null ||
        fail "$name validationActions lack $action: $(jq -c '.spec.validationActions' <<<"$doc")"
    done
    for action in $forbidden; do
      jq -e --arg a "$action" '(.spec.validationActions // []) | index($a) == null' <<<"$doc" >/dev/null ||
        fail "$name validationActions hold $action: $(jq -c '.spec.validationActions' <<<"$doc")"
    done
  done
}

@test "E2E params extend the production params with fixture-only entries" {
  for file in "$PROD_GOLDEN_PARAMS" "$PROD_REGISTRY_PARAMS" "$E2E_GOLDEN_PARAMS" "$E2E_REGISTRY_PARAMS"; do
    [ -f "$REPO_ROOT/$file" ] || fail "$file does not exist"
  done
  prod_golden="$(configmap_json "$REPO_ROOT/$PROD_GOLDEN_PARAMS")"
  e2e_golden="$(configmap_json "$REPO_ROOT/$E2E_GOLDEN_PARAMS")"
  prod_registries="$(configmap_json "$REPO_ROOT/$PROD_REGISTRY_PARAMS")"
  jq -e '.kind == "ConfigMap" and .metadata.name == "harborlab-registries" and .metadata.namespace == "kyverno"' \
    <<<"$prod_registries" >/dev/null || fail "$PROD_REGISTRY_PARAMS is not the ConfigMap kyverno/harborlab-registries"

  # Golden catalog: every supported production entry present, no production entry changed (production deprecated
  # or eol versions may be left out: the E2E cases use their own fixture bases), extra entries fixture-only,
  # deprecated or eol.
  jq -en --argjson prod "$prod_golden" --argjson e2e "$e2e_golden" \
    '($prod.data | to_entries | map(select(.key | startswith("sha256."))) | any(.value == "supported"))
      and ($prod.data | to_entries | all(.key as $k | .value as $v | ($e2e.data[$k] // null) as $e
        | if $v == "supported" then $e == $v else $e == null or $e == $v end))' >/dev/null ||
    fail "$E2E_GOLDEN_PARAMS drops a supported entry or changes an entry of $PROD_GOLDEN_PARAMS"
  catalog_keys="$(yq -o=json '[.images[].digest | "sha256." + sub("^sha256:"; "")]' "$REPO_ROOT/$CATALOG")"
  extra="$(jq -c --argjson prod "$prod_golden" '.data | with_entries(.key as $k | select(($prod.data | has($k)) | not))' <<<"$e2e_golden")"
  jq -e --argjson catalog "$catalog_keys" 'keys | all(. as $k | $catalog | index($k) == null)' <<<"$extra" >/dev/null ||
    fail "a fixture entry of $E2E_GOLDEN_PARAMS is a digest of $CATALOG: $extra"
  jq -e 'to_entries | all(.value == "deprecated" or .value == "eol")
      and any(.value == "deprecated") and any(.value == "eol")' <<<"$extra" >/dev/null ||
    fail "$E2E_GOLDEN_PARAMS fixture entries must be deprecated or eol, with at least one of each: $extra"

  # Registries: production workload list is Harbor golden/apps; E2E adds only the GHCR fixtures prefix.
  prod_workload="$(list_value "$REPO_ROOT/$PROD_REGISTRY_PARAMS" workload)"
  [ "$prod_workload" = "$HARBOR_WORKLOAD_PREFIXES" ] ||
    fail "$PROD_REGISTRY_PARAMS workload list is not exactly Harbor golden and apps: $prod_workload"
  prod_platform="$(list_value "$REPO_ROOT/$PROD_REGISTRY_PARAMS" platform)"
  [ -n "$prod_platform" ] || fail "$PROD_REGISTRY_PARAMS has an empty platform allow-list"
  e2e_workload="$(list_value "$REPO_ROOT/$E2E_REGISTRY_PARAMS" workload)"
  [ "$e2e_workload" = "$(printf '%s\n%s\n' "$prod_workload" "$FIXTURES_PREFIX" | sort)" ] ||
    fail "$E2E_REGISTRY_PARAMS workload list is not the production list plus $FIXTURES_PREFIX: $e2e_workload"
  [ "$(list_value "$REPO_ROOT/$E2E_REGISTRY_PARAMS" platform)" = "$prod_platform" ] ||
    fail "$E2E_REGISTRY_PARAMS platform allow-list differs from $PROD_REGISTRY_PARAMS"

  # kyverno test contexts hold the E2E params verbatim and no mocked image data; every suite reads the
  # context of its tier (tests/kyverno/<tier>/context.yaml).
  while IFS= read -r -d '' suite; do
    tier="${suite#"$REPO_ROOT/$KYVERNO_SUITES/"}"
    tier="${tier%%/*}"
    context="$(realpath -m "$(dirname "$suite")/$(yq '.context // ""' "$suite")")"
    [ "$context" = "$REPO_ROOT/$KYVERNO_SUITES/$tier/context.yaml" ] ||
      fail "${suite#"$REPO_ROOT/"} context is not $KYVERNO_SUITES/$tier/context.yaml: ${context#"$REPO_ROOT/"}"
  done < <(find "$REPO_ROOT/$KYVERNO_SUITES" -name kyverno-test.yaml -print0)
  # "<suite>|<E2E params file>"
  for pair in "workload|$E2E_GOLDEN_PARAMS" "workload|$E2E_REGISTRY_PARAMS" "platform|$E2E_REGISTRY_PARAMS"; do
    IFS='|' read -r suite file <<<"$pair"
    context="$REPO_ROOT/tests/kyverno/$suite/context.yaml"
    yq -e '.spec.images == null' "$context" >/dev/null || fail "tests/kyverno/$suite/context.yaml mocks image data"
    name="$(yq '.metadata.name' "$REPO_ROOT/$file")"
    in_context="$(NAME="$name" yq -o=json -I=0 \
      '.spec.resources[] | select(.kind == "ConfigMap" and .metadata.name == strenv(NAME)) | .data' "$context")"
    [ -n "$in_context" ] || fail "tests/kyverno/$suite/context.yaml has no ConfigMap $name"
    jq -e --argjson want "$(yq -o=json -I=0 '.data' "$REPO_ROOT/$file")" '. == $want' <<<"$in_context" >/dev/null ||
      fail "tests/kyverno/$suite/context.yaml ConfigMap $name differs from $file"
  done

  # Fixture bases match the status each case stands for.
  for case in "compliant|supported" "missing-labels|supported" "deprecated-base|deprecated" "eol-base|eol" "unknown-base|"; do
    IFS='|' read -r fixture status <<<"$case"
    digest="$(fixture_base_digest "$fixture")" || return 1
    actual="$(jq -r --arg k "$(digest_key "$digest")" '.data[$k] // ""' <<<"$e2e_golden")"
    [ "$actual" = "$status" ] ||
      fail "$FIXTURE_SOURCES/$fixture base $digest has status '$actual' in $E2E_GOLDEN_PARAMS, expected '$status'"
  done
}

@test "admission suites consume the fixtures by the sha-<commit> tag pinned in images/demo-fixtures.yaml" {
  commit="$(yq '.commit' "$REPO_ROOT/$FIXTURE_PIN")"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail "$FIXTURE_PIN .commit is not a full commit sha: $commit"
  tag="$("$REPO_ROOT/$FIXTURE_TAG_HELPER")"
  [ "$tag" = "sha-$commit" ] || fail "$FIXTURE_TAG_HELPER prints '$tag', expected sha-$commit"

  # Every fixture reference of the kyverno and Chainsaw cases names the pinned tag through the helper.
  refs="$(grep -rhoE 'harborlab/(fixtures|offlist)/[a-z0-9-]+[:@][^[:space:]"]*' \
    "$REPO_ROOT/tests/kyverno" "$REPO_ROOT/tests/chainsaw" | sort -u)"
  [ -n "$refs" ] || fail "no fixture reference under tests/kyverno or tests/chainsaw"
  moving="$(grep -vE ':(\$\{FIXTURE_TAG\}|\$\(\.\./\.\./\.\./fixtures/fixture-tag\.sh\))$' <<<"$refs" || true)"
  [ -z "$moving" ] || fail "fixture references not on the pinned tag: $(paste -sd ' ' - <<<"$moving")"
}
