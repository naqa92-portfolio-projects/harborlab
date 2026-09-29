#!/usr/bin/env bash
# Platform lint of a git work tree (default: this repository): runs every check, prints
# `FAILED <check>` per failing one and exits non-zero iff one failed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN_REFERENCE='^(ghcr\.io/naqa92-portfolio-projects/harborlab/golden|harbor\.127\.0\.0\.1\.nip\.io/golden)/([a-z0-9-]+)(:[^@/]+)?@(sha256:[0-9a-f]{64})$'
PINNED_USES='^([^@[:space:]]+@[0-9a-f]{40}|\./.+|docker://[^@[:space:]]+@sha256:[0-9a-f]{64})$'
# The only BuildKit frontend a `# syntax=` directive may name: a custom one decides the base itself.
OFFICIAL_FRONTEND='^(docker\.io/)?docker/dockerfile(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$'

TARGET="$(cd "${1:-$REPO_ROOT}" 2>/dev/null && pwd)" || {
  echo "ERROR: ${1:-} is not a directory" >&2
  exit 2
}
git -C "$TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  echo "ERROR: $TARGET is not a git work tree" >&2
  exit 2
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/tree"
mkdir -p "$TREE"

# File-based checks see the tracked and untracked, non-ignored files, without tests/** (deliberately
# non-compliant fixtures).
(cd "$TARGET" && git ls-files -z --cached --others --exclude-standard |
  while IFS= read -r -d '' path; do
    [[ "$path" == tests/* ]] && continue
    [ -f "$path" ] && printf '%s\0' "$path"
  done | tar --null -T - -cf -) | tar -C "$TREE" -xf -

mapfile -t WORKFLOWS < <(find "$TREE/.github/workflows" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | sort)
mapfile -t DOCKERFILES < <(cd "$TREE" && find . -type f \( -name Dockerfile -o -name 'Dockerfile.*' -o -name '*.Dockerfile' -o -name Containerfile \) |
  sed 's|^\./||' | sort)

check_zizmor() {
  [ "${#WORKFLOWS[@]}" -gt 0 ] || return 0
  zizmor --no-progress "${WORKFLOWS[@]}"
}

check_pinned_actions() {
  local workflow uses status=0
  for workflow in "${WORKFLOWS[@]}"; do
    while IFS= read -r uses; do
      [ -n "$uses" ] || continue
      if [[ ! "$uses" =~ $PINNED_USES ]]; then
        echo "${workflow#"$TREE/"}: '$uses' is not pinned to a commit SHA"
        status=1
      fi
    done < <(yq -o=json '.' "$workflow" |
      jq -r '(.jobs // {})[] | (.uses // empty), ((.steps // [])[] | .uses // empty)') || status=1
  done
  return "$status"
}

check_gitleaks() {
  local config=()
  [ ! -f "$TARGET/.gitleaks.toml" ] || config=(--config "$TARGET/.gitleaks.toml")
  gitleaks git --no-banner --redact --log-level warn "${config[@]}" "$TARGET"
}

check_hadolint() {
  [ "${#DOCKERFILES[@]}" -gt 0 ] || return 0
  (cd "$TREE" && hadolint --failure-threshold error "${DOCKERFILES[@]}")
}

check_trivy_config() {
  trivy config --quiet --severity HIGH,CRITICAL --exit-code 1 "$TREE"
}

check_kube_linter() {
  kube-linter lint "$TREE"
}

# Every FROM (other than a reference to an earlier stage) is a digest-pinned golden image whose
# (name, digest) is a supported entry of the target's catalog, built by BuildKit's own frontend.
check_from_golden() {
  local catalog="$TARGET/images/catalog.yaml" supported dockerfile from status=0 stages governed=()
  for dockerfile in "${DOCKERFILES[@]}"; do
    [[ "$dockerfile" == images/golden/* || "$dockerfile" == spike/* ]] || governed+=("$dockerfile")
  done
  [ "${#governed[@]}" -gt 0 ] || return 0
  supported="$(yq -r '.images[] | select(.status == "supported") | .name + "@" + .digest' "$catalog" 2>/dev/null)" || {
    echo "images/catalog.yaml: missing or unreadable"
    return 1
  }
  for dockerfile in "${governed[@]}"; do
    while IFS= read -r frontend; do
      if [[ ! "$frontend" =~ $OFFICIAL_FRONTEND ]]; then
        echo "$dockerfile: # syntax=$frontend names a custom BuildKit frontend"
        status=1
      fi
    done < <(awk 'BEGIN { directives = 1 }
      directives && /^#[[:space:]]*[A-Za-z]+[[:space:]]*=/ {
        line = $0; sub(/^#[[:space:]]*/, "", line)
        key = tolower(substr(line, 1, index(line, "=") - 1)); gsub(/[[:space:]]/, "", key)
        value = substr(line, index(line, "=") + 1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        if (key == "syntax") print value
        next
      }
      { directives = 0 }' "$TREE/$dockerfile")
    stages=" "
    while read -r from alias; do
      if [[ "$stages" == *" $from "* ]]; then
        :
      elif [[ ! "$from" =~ $GOLDEN_REFERENCE ]]; then
        echo "$dockerfile: FROM $from is not a digest-pinned golden image"
        status=1
      elif ! grep -qxF "${BASH_REMATCH[2]}@${BASH_REMATCH[4]}" <<<"$supported"; then
        echo "$dockerfile: FROM $from is not a supported entry of images/catalog.yaml"
        status=1
      fi
      [ -z "$alias" ] || stages+="$alias "
    done < <(awk 'toupper($1) == "FROM" {
        image = ""; alias = ""
        for (i = 2; i <= NF; i++) {
          if (image == "" && $i !~ /^--/) image = $i
          else if (image != "" && toupper($i) == "AS" && i < NF) alias = $(i + 1)
        }
        print image, alias
      }' "$TREE/$dockerfile")
  done
  return "$status"
}

failed=0
for check in zizmor pinned-actions gitleaks hadolint trivy-config kube-linter from-golden; do
  echo "==> $check"
  if ! "check_${check//-/_}" >"$WORK/$check.log" 2>&1; then
    cat "$WORK/$check.log"
    echo "FAILED $check"
    failed=1
  fi
done
exit "$failed"
