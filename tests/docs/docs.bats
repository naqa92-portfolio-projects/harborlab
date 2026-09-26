#!/usr/bin/env bats
# Documentation required by the PRD, read statically from the repository.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
THREAT_MODEL=docs/THREAT-MODEL.md
BOOTSTRAP_NAMESPACES=(kube-system cilium argocd kyverno)

fail() {
  echo "$*" >&2
  return 1
}

@test "threat model documents the bootstrap namespace exclusion" {
  [ -s "$REPO_ROOT/$THREAT_MODEL" ] || fail "$THREAT_MODEL does not exist or is empty"

  # The Markdown section (up to the next heading of any level) whose heading names the bootstrap tier.
  section="$(awk '
    /^#+[[:space:]]/ { inside = (tolower($0) ~ /bootstrap/) }
    inside { print }
  ' "$REPO_ROOT/$THREAT_MODEL")"
  [ -n "$section" ] || fail "$THREAT_MODEL has no heading naming the bootstrap namespaces"

  grep -qiE 'exclu(ded|des|de|sion)' <<<"$section" ||
    fail "the bootstrap section of $THREAT_MODEL does not state an exclusion"
  for namespace in "${BOOTSTRAP_NAMESPACES[@]}"; do
    grep -qE "(^|[^a-z0-9-])$namespace([^a-z0-9-]|$)" <<<"$section" ||
      fail "the bootstrap section of $THREAT_MODEL does not name the $namespace namespace"
  done
}
