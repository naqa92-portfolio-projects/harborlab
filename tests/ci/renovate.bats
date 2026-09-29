#!/usr/bin/env bats
# What Renovate may change, evaluated from renovate.json: packageRules are applied in order to a
# hypothetical update, as Renovate merges matching rules (a later match overrides an earlier one).
# Only the matchers below are modelled; a rule using another matcher fails the test so it gets modelled.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
RENOVATE_CONFIG=renovate.json
HELLO_JAVA_POM=apps/hello-java/pom.xml
MODELLED_MATCHERS='["matchDatasources", "matchPackageNames", "matchDepNames", "matchFileNames", "matchUpdateTypes", "matchManagers"]'

fail() {
  echo "$*" >&2
  return 1
}

setup() {
  CONFIG="$(jq '.' "$REPO_ROOT/$RENOVATE_CONFIG")" || fail "$RENOVATE_CONFIG is not valid JSON"
}

# Renovate's effective `enabled` for an update: {file, manager, datasource, package, updateType}.
effective_enabled() {
  jq -r --argjson update "$1" --argjson modelled "$MODELLED_MATCHERS" '
    # Renovate glob (minimatch) or /regex/ pattern, possibly negated with a leading "!".
    def glob_regex: "^" + (gsub("(?<c>[.+^$(){}|\\[\\]\\\\])"; "\\\(.c)")
      | gsub("\\*\\*/"; "\u0001") | gsub("\\*\\*"; "\u0002") | gsub("\\*"; "[^/]*") | gsub("\\?"; "[^/]")
      | gsub("\u0001"; "(.*/)?") | gsub("\u0002"; ".*")) + "$";
    def one_match($value):
      if startswith("/") then (ltrimstr("/") | sub("/[a-z]*$"; "")) as $re | ($value | test($re))
      else ($value | test(glob_regex)) end;
    def matches($patterns; $value):
      ($patterns | map(select(startswith("!") | not))) as $positive
      | ($patterns | map(select(startswith("!")) | ltrimstr("!"))) as $negative
      | (($positive | length) == 0 or any($positive[]; one_match($value)))
        and all($negative[]; one_match($value) | not);
    def applies($u):
      ((.matchDatasources // null) as $m | $m == null or ($m | index($u.datasource)) != null)
      and ((.matchManagers // null) as $m | $m == null or ($m | index($u.manager)) != null)
      and ((.matchUpdateTypes // null) as $m | $m == null or ($m | index($u.updateType)) != null)
      and ((.matchPackageNames // null) as $m | $m == null or matches($m; $u.package))
      and ((.matchDepNames // null) as $m | $m == null or matches($m; $u.package))
      and ((.matchFileNames // null) as $m | $m == null or matches($m; $u.file));
    (.packageRules // []) as $rules
    | ([$rules[] | keys[] | select(startswith("match") or startswith("exclude"))] - $modelled) as $unknown
    | if ($unknown | length) > 0 then "unmodelled matcher: \($unknown | unique | join(", "))"
      else reduce ($rules[] | select(applies($update))) as $rule (true;
        if $rule | has("enabled") then $rule.enabled else . end) end
  ' <<<"$CONFIG"
}

@test "Renovate updates the DHI bases of golden images by digest only" {
  for file in $(git -C "$REPO_ROOT" ls-files 'images/golden/**Dockerfile'); do
    package="$(awk 'toupper($1) == "FROM" { for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; exit } }' "$REPO_ROOT/$file")"
    package="${package%@*}"
    package="${package%:*}"
    [[ "$package" == dhi.io/* ]] || continue
    found=1
    for update_type in major minor patch; do
      update="$(jq -nc --arg f "$file" --arg p "$package" --arg t "$update_type" \
        '{file: $f, manager: "dockerfile", datasource: "docker", package: $p, updateType: $t}')"
      enabled="$(effective_enabled "$update")"
      [ "$enabled" = false ] ||
        fail "Renovate would propose a $update_type update of $package in $file ($RENOVATE_CONFIG: $enabled): a pinned lifecycle version would move"
    done
    update="$(jq -nc --arg f "$file" --arg p "$package" \
      '{file: $f, manager: "dockerfile", datasource: "docker", package: $p, updateType: "digest"}')"
    enabled="$(effective_enabled "$update")"
    [ "$enabled" = true ] || fail "Renovate would not propose digest updates of $package in $file ($enabled)"
  done
  [ "${found:-0}" -eq 1 ] || fail "no golden Dockerfile under images/golden is based on dhi.io"
}

@test "hello-java Tomcat override is tracked by Renovate or removed" {
  pom="$REPO_ROOT/$HELLO_JAVA_POM"
  version="$(yq -p=xml -o=json '.project.properties["tomcat.version"] // ""' "$pom")" ||
    fail "$HELLO_JAVA_POM is not valid XML"
  version="$(jq -r '.' <<<"$version")"
  [ -n "$version" ] || return 0

  # Tracked by Renovate's maven manager: the property is the version of a declared Tomcat dependency.
  yq -p=xml -o=json '.project.dependencies.dependency // [] | [.] | flatten | .[]' "$pom" |
    jq -se 'any(.[]; (.artifactId // "" | test("^tomcat-embed-")) and .version == "${tomcat.version}")' >/dev/null &&
    return 0

  # Or tracked by a regex custom manager whose pattern captures this very property.
  content="$(cat "$pom")"
  tracked="$(jq -r --arg file "$HELLO_JAVA_POM" --arg content "$content" '
    [(.customManagers // [])[]
      | select(.customType == "regex")
      | select(any((.managerFilePatterns // .fileMatch // [])[]; . as $p
          | ($p | ltrimstr("/") | sub("/$"; "")) as $re | $file | test($re)))
      | . as $m | .matchStrings[] | . as $pattern
      | ($content | [capture($pattern; "g")] | .[]
          | select((.currentValue // "") != "")
          | {value: .currentValue, dep: (.depName // $m.depNameTemplate // "")})
    ] | map(select(.dep | test("tomcat"))) | map(.value) | join(" ")' <<<"$CONFIG")"
  grep -qw -- "$version" <<<"$tracked" ||
    fail "$HELLO_JAVA_POM forces tomcat.version $version, which no Renovate manager tracks (captured: ${tracked:-nothing})"
}
