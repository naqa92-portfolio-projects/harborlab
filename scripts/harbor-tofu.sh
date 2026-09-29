#!/usr/bin/env bash
# Runs OpenTofu on tofu/harbor/ logged into OpenBao as `harbor-tofu`: configure | plan | tofu <args>;
# `seed` only generates the missing robot and webhook secrets in OpenBao.
# Only tofu writes to stdout; secrets travel through pipes and the environment, never argv.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
OPENBAO_INIT="$REPO_ROOT/.local/openbao/init.json"
LOCAL_CA="$REPO_ROOT/.local/ca/ca.crt"
TOFU_DIR="$REPO_ROOT/tofu/harbor"
HARBOR_URL=https://harbor.127.0.0.1.nip.io
HARBOR_READY_TIMEOUT_SECONDS=600
OPENBAO_ROLE=harbor-tofu

# "<Harbor robot name>|<OpenBao KV path under secret/>"
ROBOTS=(
  'robot$dt-bridge|platform/harbor-robot-dt-bridge'
)

log() { printf '==> %s\n' "$*" >&2; }
die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  die "usage: $0 configure | plan | seed | tofu <args>"
}

[ "$#" -ge 1 ] || usage
MODE="$1"
shift
case "$MODE" in configure | plan | seed | tofu) ;; *) usage ;; esac

[ -s "$KUBECONFIG" ] || die "platform is not up: $KUBECONFIG missing (run task up)"
[ -s "$LOCAL_CA" ] || die "$LOCAL_CA missing (run task up)"

WORK="$(mktemp -d)"
FORWARD_PID=""
cleanup() {
  [ -z "$FORWARD_PID" ] || kill "$FORWARD_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
chmod 700 "$WORK"
umask 077

# Runs a shell script in the OpenBao container with the root token on stdin.
bao_root() {
  local script="$1"
  shift
  [ -s "$OPENBAO_INIT" ] || die "$OPENBAO_INIT missing (run task up)"
  { jq -r .root_token "$OPENBAO_INIT"; cat; } |
    kubectl -n openbao exec -i openbao-0 -c openbao -- sh -ec 'read -r BAO_TOKEN; export BAO_TOKEN; '"$script" sh "$@"
}

# Robot secrets are generated once; Harbor requires upper case, lower case and digits.
seed_robot_secrets() {
  local entry name path value
  for entry in "${ROBOTS[@]}"; do
    IFS='|' read -r name path <<<"$entry"
    if bao_root 'bao kv get -mount=secret "$1" >/dev/null 2>&1' "$path" </dev/null; then
      continue
    fi
    log "generating the $name secret into OpenBao secret/$path"
    value="$(openssl rand -base64 96 | tr -dc 'A-Za-z0-9')"
    printf '%s\n' "${value:0:32}" | jq -Rn --arg n "$name" '{username: $n, password: (input + "Aa1")}' |
      bao_root 'bao kv put -mount=secret "$1" - >/dev/null' "$path"
  done
}

# Shared secret Harbor sends to dt-bridge in the webhook Authorization header; generated once.
WEBHOOK_SECRET_PATH=platform/harbor-webhook-dt-bridge
seed_webhook_secret() {
  if bao_root 'bao kv get -mount=secret "$1" >/dev/null 2>&1' "$WEBHOOK_SECRET_PATH" </dev/null; then
    return
  fi
  log "generating the dt-bridge webhook secret into OpenBao secret/$WEBHOOK_SECRET_PATH"
  openssl rand -hex 32 | jq -Rn '{token: input}' |
    bao_root 'bao kv put -mount=secret "$1" - >/dev/null' "$WEBHOOK_SECRET_PATH"
}

# OpenBao is reached through a port-forward bound to 127.0.0.1 for the duration of the run.
start_openbao_forward() {
  local port=""
  kubectl -n openbao port-forward svc/openbao :8200 >"$WORK/port-forward.log" 2>&1 &
  FORWARD_PID=$!
  for _ in $(seq 1 60); do
    port="$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) .*/\1/p' "$WORK/port-forward.log" | head -n 1)"
    [ -z "$port" ] || break
    kill -0 "$FORWARD_PID" 2>/dev/null || die "port-forward to openbao/openbao failed: $(cat "$WORK/port-forward.log")"
    sleep 1
  done
  [ -n "$port" ] || die "port-forward to openbao/openbao did not start"
  export BAO_ADDR="http://127.0.0.1:$port" VAULT_ADDR="http://127.0.0.1:$port"
}

# Kubernetes-auth login with the harbor-tofu ServiceAccount; the token only reaches tofu's environment.
openbao_login() {
  local token
  token="$(kubectl -n openbao create token "$OPENBAO_ROLE" --duration=10m |
    jq -Rn --arg role "$OPENBAO_ROLE" '{role: $role, jwt: input}' |
    curl -sS --fail-with-body -X POST --data @- "$BAO_ADDR/v1/auth/kubernetes/login" |
    jq -r '.auth.client_token // empty')"
  [ -n "$token" ] || die "OpenBao Kubernetes login with role $OPENBAO_ROLE failed"
  export BAO_TOKEN="$token" VAULT_TOKEN="$token"
}

# The Harbor provider trusts the system roots plus the local CA that signs the Gateway certificate.
trust_local_ca() {
  cat "${SSL_CERT_FILE:-${NIX_SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}}" "$LOCAL_CA" >"$WORK/ca-bundle.crt"
  export SSL_CERT_FILE="$WORK/ca-bundle.crt"
}

wait_for_harbor() {
  local deadline=$((SECONDS + HARBOR_READY_TIMEOUT_SECONDS))
  until [ "$(curl -sS --max-time 5 --cacert "$LOCAL_CA" "$HARBOR_URL/api/v2.0/ping" 2>/dev/null)" = Pong ]; do
    [ "$SECONDS" -lt "$deadline" ] || die "Harbor does not answer on $HARBOR_URL"
    sleep 5
  done
}

run_tofu() {
  tofu -chdir="$TOFU_DIR" "$@"
}

export TF_IN_AUTOMATION=1 TF_INPUT=0

if [ "$MODE" = configure ] || [ "$MODE" = seed ]; then
  seed_robot_secrets
  seed_webhook_secret
fi
[ "$MODE" != seed ] || exit 0
start_openbao_forward
openbao_login
trust_local_ca
wait_for_harbor
run_tofu init -input=false -lockfile=readonly >&2

status=0
case "$MODE" in
  configure) run_tofu apply -input=false -auto-approve || status=$? ;;
  plan) run_tofu plan -input=false -detailed-exitcode || status=$? ;;
  tofu) run_tofu "$@" || status=$? ;;
esac
exit "$status"
