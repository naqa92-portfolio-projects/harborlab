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

REQUIRED_DOCS=(README.md docs/ARCHITECTURE.md docs/THREAT-MODEL.md docs/DEMO.md docs/ROADMAP.md)
ROADMAP=docs/ROADMAP.md
DEMO=docs/DEMO.md
README=README.md
ADR_GLOB='docs/adr/[0-9][0-9][0-9][0-9]-*.md'
# A paragraph reads as French when it holds at least this many French function words, making up at least
# this share of its words (English prose has none of them).
FRENCH_MIN_WORDS=3
FRENCH_MIN_PERCENT=10
FRENCH_STOP_WORDS='le la les des du une et est dans pour avec sur pas qui que sont aux nous vous ils elle mais cette ces leur leurs ou'

# Lines of the Markdown section of $1 whose heading matches the extended regexp $2 (case-insensitive), up to the
# next heading of the same or a higher level.
section() {
  awk -v re="$2" '
    /^#+[[:space:]]/ {
      level = length($1)
      if (inside && level <= inside_level) inside = 0
      if (!inside && tolower($0) ~ tolower(re)) { inside = 1; inside_level = level }
    }
    inside { print }
  ' "$REPO_ROOT/$1"
}

# Title (first level-1 heading) of the ADR file $1.
adr_title() {
  awk '/^#[[:space:]]/ { sub(/^#[[:space:]]+/, ""); print; exit }' "$1"
}

@test "required documents exist" {
  missing=()
  for doc in "${REQUIRED_DOCS[@]}"; do
    [ -s "$REPO_ROOT/$doc" ] || missing+=("$doc")
  done
  [ "${#missing[@]}" -eq 0 ] || fail "missing or empty: ${missing[*]}"
}

@test "one ADR per structuring decision" {
  shopt -s nullglob
  adrs=($REPO_ROOT/$ADR_GLOB)
  [ "${#adrs[@]}" -gt 0 ] || fail "no ADR matches $ADR_GLOB"

  # decision label | extended regexps its ADR title must all match (case-insensitive), separated by ' && '
  decisions=(
    'Kyverno CEL-only|kyverno && (^|[^a-z])cel([^a-z]|$)'
    'Kubescape over Trivy Operator + Falco|kubescape.*(over|instead of|rather than|replac).*trivy[ -]operator && falco'
    'Dependency-Track + dt-bridge|dependency-track && dt-bridge'
    'OpenTofu + goharbor provider over harbor-cli|opentofu.*goharbor.*(over|instead of|rather than).*harbor-cli'
    'transparent mirror + trust tiers|transparent.*mirror && trust tier'
    'keyless signing|keyless && sign'
  )
  problems=()
  matched=()
  for entry in "${decisions[@]}"; do
    label="${entry%%|*}"
    patterns="${entry#*|}"
    found=""
    for adr in "${adrs[@]}"; do
      title="$(adr_title "$adr" | tr '[:upper:]' '[:lower:]')"
      ok=1
      while read -r pattern; do
        grep -qE -- "$pattern" <<<"$title" || ok=0
      done < <(sed 's/ && /\n/g' <<<"$patterns")
      [ "$ok" -eq 1 ] && found+="${adr##*/} "
    done
    if [ -z "$found" ]; then
      problems+=("no ADR titled for '$label'")
    else
      matched+=($found)
    fi
  done
  distinct="$(printf '%s\n' "${matched[@]}" | sort -u | grep -c . || true)"
  [ "${#problems[@]}" -gt 0 ] || [ "$distinct" -ge "${#decisions[@]}" ] ||
    problems+=("the ${#decisions[@]} decisions share ADRs: only $distinct distinct file(s) match")

  for adr in "${adrs[@]}"; do
    title="$(adr_title "$adr" | tr '[:upper:]' '[:lower:]')"
    [ -n "$title" ] || problems+=("${adr##*/} has no level-1 title")
    ! grep -qE 'harbor-cli.*(over|instead of|rather than).*(terraform|opentofu)' <<<"$title" ||
      problems+=("${adr##*/} records the superseded choice of harbor-cli (Decision 8 is OpenTofu + goharbor provider)")
    for heading in Context Decision Consequences; do
      grep -qE "^## $heading([[:space:]]|$)" "$adr" || problems+=("${adr##*/} has no '## $heading' section")
    done
  done
  grep -qil grype "${adrs[@]}" && grep -il grype "${adrs[@]}" | xargs grep -qi trivy ||
    problems+=("no ADR records the Grype (Kubescape) versus Trivy (CI, Harbor) divergence")

  [ "${#problems[@]}" -eq 0 ] || fail "$(printf '%s; ' "${problems[@]}")"
}

@test "documents are written in English" {
  shopt -s nullglob
  files=()
  for doc in "${REQUIRED_DOCS[@]}"; do
    [ -s "$REPO_ROOT/$doc" ] || fail "cannot check the language of $doc: it does not exist or is empty"
  done
  for doc in "$REPO_ROOT"/README.md "$REPO_ROOT"/docs/*.md "$REPO_ROOT"/docs/adr/*.md; do
    [ -f "$doc" ] && files+=("$doc")
  done

  french="$(for doc in "${files[@]}"; do
    awk '/^[[:space:]]*```/ { fenced = !fenced; next } !fenced { print }' "$doc" |
      awk -v file="${doc#"$REPO_ROOT"/}" -v stop="$FRENCH_STOP_WORDS" -v min_words="$FRENCH_MIN_WORDS" \
        -v min_percent="$FRENCH_MIN_PERCENT" '
        BEGIN { RS = ""; n = split(stop, s, " "); for (i = 1; i <= n; i++) is_stop[s[i]] = 1 }
        {
          text = $0
          gsub(/`[^`]*`/, " ", text)
          gsub(/\]\([^)]*\)/, "] ", text)
          count = split(tolower(text), words, /[^a-z]+/)
          total = 0; hits = 0
          for (i = 1; i <= count; i++) if (words[i] != "") { total++; if (words[i] in is_stop) hits++ }
          if (hits >= min_words && hits * 100 >= total * min_percent)
            printf "%s: \"%s\" (%d of %d words are French function words)\n", file, substr($0, 1, 80), hits, total
        }'
  done)"
  [ -z "$french" ] || fail "paragraphs read as French: $french"
}

@test "README documents the prerequisites and the memory budget measurement" {
  [ -s "$REPO_ROOT/$README" ] || fail "$README does not exist or is empty"
  problems=()

  prerequisites="$(section "$README" 'prerequisite')"
  if [ -z "$prerequisites" ]; then
    problems+=("no heading naming the prerequisites")
  else
    for pattern in 'devbox' 'docker' '(^|[^a-z])gh([^a-z]|$)|github cli' 'dhi_token' 'dhi_username' '\.env' '16 ?gib'; do
      grep -qiE -- "$pattern" <<<"$prerequisites" || problems+=("the prerequisites section does not mention /$pattern/")
    done
  fi

  memory="$(section "$README" 'memory')"
  if [ -z "$memory" ]; then
    problems+=("no heading naming the memory budget")
  else
    for pattern in 'kubectl top nodes' 'working set' 'page cache' '12 ?gib'; do
      grep -qiE -- "$pattern" <<<"$memory" || problems+=("the memory section does not mention /$pattern/")
    done
  fi
  grep -qE 'task up' "$REPO_ROOT/$README" || problems+=("$README does not say how to start the platform (task up)")

  [ "${#problems[@]}" -eq 0 ] || fail "$README: $(printf '%s; ' "${problems[@]}")"
}

@test "roadmap lists the out-of-scope items and the tracked upstream issues" {
  [ -s "$REPO_ROOT/$ROADMAP" ] || fail "$ROADMAP does not exist or is empty"
  problems=()
  # item | extended regexps the roadmap must all match (case-insensitive), separated by ' && '
  items=(
    'air-gap bundle|air[- ]?gap'
    'Gatekeeper/Rego comparison|gatekeeper && rego'
    'Buildah builds|buildah'
    'chart relocation as OCI|relocat && chart && oci'
    'DependencyTrack/dependency-track#6132|dependency-track(#|/issues/)6132'
    'DependencyTrack/dependency-track#6957|dependency-track(#|/issues/)6957'
    'kyverno/sdk#125|kyverno/sdk(#|/issues/)125'
  )
  for entry in "${items[@]}"; do
    label="${entry%%|*}"
    while read -r pattern; do
      grep -qiE -- "$pattern" "$REPO_ROOT/$ROADMAP" || { problems+=("$label (/$pattern/)"); break; }
    done < <(sed 's/ && /\n/g' <<<"${entry#*|}")
  done
  [ "${#problems[@]}" -eq 0 ] || fail "$ROADMAP does not list: $(printf '%s; ' "${problems[@]}")"
}

@test "DEMO.md documents every demo scenario" {
  [ -s "$REPO_ROOT/$DEMO" ] || fail "$DEMO does not exist or is empty"
  problems=()
  # scenario | extended regexps its DEMO.md section must all match (case-insensitive), separated by ' && '
  scenarios=(
    'unsigned|workload-image-signature && den(y|ies|ied)'
    'foreign-signer|workload-image-signature && den(y|ies|ied)'
    'non-golden-base|workload-golden-base([^-]|$) && den(y|ies|ied)'
    'deprecated-base|workload-golden-base-deprecated && warning && admit'
    'eol-base|workload-golden-base([^-]|$) && end-of-life|(^|[^a-z])eol([^a-z]|$) && den(y|ies|ied)'
    'direct-dockerhub|workload-registry && den(y|ies|ied)'
    'root|pod ?security && restricted && den(y|ies|ied)'
    'runtime-shell|kubescape && victorialogs|grafana'
    'vex|dependency-track && completed && dependency-track(#|/issues/)6132'
  )
  tasks="$(yq -r '.tasks | keys | .[]' "$REPO_ROOT/Taskfile.yml")"
  for entry in "${scenarios[@]}"; do
    scenario="${entry%%|*}"
    grep -qx "demo:$scenario" <<<"$tasks" || problems+=("Taskfile.yml defines no task demo:$scenario")
    body="$(section "$DEMO" "demo:$scenario([^a-z-]|$)")"
    if [ -z "$body" ]; then
      problems+=("no heading naming demo:$scenario")
      continue
    fi
    while read -r pattern; do
      grep -qiE -- "$pattern" <<<"$body" || problems+=("the demo:$scenario section does not match /$pattern/")
    done < <(sed 's/ && /\n/g' <<<"${entry#*|}")
  done
  grep -qE 'NAMESPACE=' "$REPO_ROOT/$DEMO" ||
    problems+=("$DEMO does not show the NAMESPACE variable of the admission scenarios")
  grep -qiE 'exits? (with )?(status |code )?0' "$REPO_ROOT/$DEMO" && grep -qiE 'non-zero' "$REPO_ROOT/$DEMO" ||
    problems+=("$DEMO does not state that a scenario exits 0 when the platform reacts and non-zero otherwise")

  [ "${#problems[@]}" -eq 0 ] || fail "$(printf '%s; ' "${problems[@]}")"
}

@test "DEMO.md shows the tier-required denial of a namespace without a tier label" {
  [ -s "$REPO_ROOT/$DEMO" ] || fail "$DEMO does not exist or is empty"
  problems=()
  stale="$(grep -niE 'admitted without any warning|no tier label: nothing reacts' "$REPO_ROOT/$DEMO" || true)"
  [ -z "$stale" ] ||
    problems+=("$DEMO says a pod in a namespace without harborlab.io/tier draws no reaction, but tier-required denies it: $(paste -sd ' ' - <<<"$stale")")
  # Blank-line separated paragraphs (code blocks included) naming tier-required.
  paragraphs="$(awk -v RS= '/tier-required/ { gsub(/\n/, " "); print }' "$REPO_ROOT/$DEMO")"
  [ -n "$paragraphs" ] || problems+=("$DEMO never names the tier-required policy")
  [ -z "$paragraphs" ] || grep -iE 'den(y|ies|ied)' <<<"$paragraphs" | grep -qiE 'exits? (with )?(status |code )?0' ||
    problems+=("no paragraph of $DEMO says a demo in a namespace without harborlab.io/tier is denied by tier-required and exits 0")
  [ "${#problems[@]}" -eq 0 ] || fail "$(printf '%s; ' "${problems[@]}")"
}
