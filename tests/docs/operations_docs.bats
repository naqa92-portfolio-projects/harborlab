#!/usr/bin/env bats
# Operator documentation: the workaround registry, node restart recovery and repository prerequisites.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
README=README.md
WORKAROUNDS=docs/WORKAROUNDS.md
# Workarounds of upstream limits the platform ships today, each named by the upstream it waits on.
KNOWN_WORKAROUNDS=(
  "kyverno/sdk#125|github.com/kyverno/sdk/(issues|pull)/12[57]"
  "DependencyTrack/dependency-track#7094|github.com/DependencyTrack/dependency-track/(issues|pull)/7094"
  "goharbor provider replication filters drift|github.com/goharbor/terraform-provider-harbor/(issues|pull)/[0-9]+"
)

fail() {
  echo "$*" >&2
  return 1
}

# Sections of WORKAROUNDS.md (one per `## ` heading), NUL-separated.
workaround_sections() {
  awk '/^## / { if (section != "") printf "%s%c", section, 0; section = $0; next }
       section != "" { section = section "\n" $0 }
       END { if (section != "") printf "%s%c", section, 0 }' "$REPO_ROOT/$WORKAROUNDS"
}

@test "WORKAROUNDS.md lists each workaround with its code location, upstream link and exit condition" {
  [ -s "$REPO_ROOT/$WORKAROUNDS" ] || fail "$WORKAROUNDS does not exist"
  count=0
  while IFS= read -r -d '' section; do
    count=$((count + 1))
    title="$(head -n 1 <<<"$section")"
    grep -qE 'https://[^ )]+' <<<"$section" || fail "$WORKAROUNDS '$title' has no upstream link"
    grep -qiE 'exit condition' <<<"$section" || fail "$WORKAROUNDS '$title' has no exit condition"
    located=false
    for path in $(grep -oE '`[^` ]+`' <<<"$section" | tr -d '`' | sed 's/:[0-9-]*$//'); do
      if [ -e "$REPO_ROOT/$path" ]; then located=true; fi
    done
    [ "$located" = true ] || fail "$WORKAROUNDS '$title' names no existing code location (a \`path\` of this repository)"
  done < <(workaround_sections)
  [ "$count" -gt 0 ] || fail "$WORKAROUNDS has no workaround section (## heading)"

  for known in "${KNOWN_WORKAROUNDS[@]}"; do
    grep -qE "https://${known#*|}" "$REPO_ROOT/$WORKAROUNDS" ||
      fail "$WORKAROUNDS does not register the workaround for ${known%%|*} (no link matching ${known#*|})"
  done
}

@test "WORKAROUNDS.md records the goharbor replication filter drift" {
  [ -s "$REPO_ROOT/$WORKAROUNDS" ] || fail "$WORKAROUNDS does not exist"
  section=""
  while IFS= read -r -d '' candidate; do
    if grep -q 'harbor_replication' <<<"$candidate" && grep -qi 'filter' <<<"$candidate"; then section="$candidate"; fi
  done < <(workaround_sections)
  [ -n "$section" ] || fail "$WORKAROUNDS has no entry on harbor_replication filters"
  grep -qE 'task harbor:(plan|configure)|-replace' <<<"$section" ||
    fail "$WORKAROUNDS harbor_replication filters entry does not say how drift is detected or repaired"
}

@test "README documents recovering a stopped node with task down and task up" {
  # The paragraph that names the recovery also names the event it recovers from.
  paragraph="$(awk 'BEGIN { RS = "" } /task down && task up|task down && devbox run -- task up|task down; task up/' "$REPO_ROOT/$README")"
  [ -n "$paragraph" ] || fail "$README never documents 'task down && task up'"
  grep -qiE 'docker (stop|start|restart)|stopped|restart|reboot' <<<"$paragraph" ||
    fail "$README documents 'task down && task up' without the node stop or restart it recovers from: $paragraph"
}

@test "README prerequisites require the branch ruleset protecting main" {
  prerequisites="$(awk '/^## Prerequisites/ { in_section = 1; next } /^## / { in_section = 0 } in_section' "$REPO_ROOT/$README")"
  [ -n "$prerequisites" ] || fail "$README has no Prerequisites section"
  grep -qiE 'ruleset|branch protection' <<<"$prerequisites" ||
    fail "$README prerequisites do not require a ruleset protecting main and prd-* branches"
  grep -qE '\bmain\b' <<<"$(grep -iE 'ruleset|branch protection' <<<"$prerequisites")" ||
    fail "$README ruleset prerequisite does not name main"
}
