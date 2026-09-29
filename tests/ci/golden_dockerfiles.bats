#!/usr/bin/env bats
# Golden layer sources, read statically: governance labels and a non-root user, no baked-in CA
# (the local CA reaches workloads at runtime through trust-manager).

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
GOLDEN_IMAGES=(python java)
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

@test "golden Dockerfiles bake no CA and run as a non-root user" {
  for name in "${GOLDEN_IMAGES[@]}"; do
    dockerfile="images/golden/$name/Dockerfile"
    [ -f "$REPO_ROOT/$dockerfile" ] || fail "$dockerfile does not exist"
    instructions "$REPO_ROOT/$dockerfile" >"$BATS_TEST_TMPDIR/$name.instructions"

    copied="$(grep -iE '^[[:space:]]*(COPY|ADD)[[:space:]]' "$BATS_TEST_TMPDIR/$name.instructions" |
      grep -iE "$CERTIFICATE_PATTERN" || true)"
    [ -z "$copied" ] || fail "$dockerfile copies a certificate into the image: $copied"
    installed="$(grep -iE '^[[:space:]]*RUN[[:space:]]' "$BATS_TEST_TMPDIR/$name.instructions" |
      grep -iE "$CA_INSTALL_PATTERN" || true)"
    [ -z "$installed" ] || fail "$dockerfile installs a CA into the image trust store: $installed"

    last_from="$(grep -inE '^[[:space:]]*FROM[[:space:]]' "$BATS_TEST_TMPDIR/$name.instructions" | tail -1 | cut -d: -f1)"
    [ -n "$last_from" ] || fail "$dockerfile has no FROM"
    user_line="$(grep -inE '^[[:space:]]*USER[[:space:]]' "$BATS_TEST_TMPDIR/$name.instructions" | tail -1)"
    [ -n "$user_line" ] || fail "$dockerfile sets no USER"
    [ "${user_line%%:*}" -gt "$last_from" ] || fail "$dockerfile sets no USER in its final stage"
    user="$(awk '{ print $2 }' <<<"${user_line#*:}")"
    user="${user%%:*}"
    [ -n "$user" ] || fail "$dockerfile has an empty USER"
    [ "$user" != root ] && [ "$user" != 0 ] || fail "$dockerfile runs as root: ${user_line#*:}"
  done
}
