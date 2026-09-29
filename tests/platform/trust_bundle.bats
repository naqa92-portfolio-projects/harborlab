#!/usr/bin/env bats
# Local CA trust delivered at runtime by trust-manager, live against the cluster started by `task up`.
# Only the CA's public certificate is read (key `tls.crt`); the CA private key is never fetched.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
HARBOR_HOST=harbor.127.0.0.1.nip.io
TRUST_APPLICATION=trust-manager
TRUST_BUNDLE=harborlab-trust
PEM_KEY=ca.crt
PKCS12_KEY=truststore.p12
CA_NAMESPACE=cert-manager
CA_SECRET=harborlab-ca
GATEWAY_TLS_NAMESPACE=gateway
GATEWAY_TLS_SECRET=wildcard-nip-io-tls
WORKLOAD_LABEL_KEY=harborlab.io/tier
WORKLOAD_LABEL_VALUE=workload
WORKLOAD_NAMESPACE=trust-bundle-test-workload
PLAIN_NAMESPACE=trust-bundle-test-plain
SYNC_TIMEOUT_SECONDS=120

fail() {
  echo "$*" >&2
  return 1
}

setup_file() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  kubectl -n "$CA_NAMESPACE" get secret "$CA_SECRET" -o jsonpath='{.data.tls\.crt}' | base64 -d \
    >"$BATS_FILE_TMPDIR/local-ca.crt"
  [ -s "$BATS_FILE_TMPDIR/local-ca.crt" ] || fail "Secret $CA_NAMESPACE/$CA_SECRET has no tls.crt"
}

setup() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  LOCAL_CA="$BATS_FILE_TMPDIR/local-ca.crt"
  LOCAL_CA_FINGERPRINT="$(openssl x509 -in "$LOCAL_CA" -noout -fingerprint -sha256 | cut -d= -f2)"
  [ -n "$LOCAL_CA_FINGERPRINT" ] || fail "tls.crt of Secret $CA_NAMESPACE/$CA_SECRET is not a certificate"
}

teardown_file() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  kubectl delete namespace "$WORKLOAD_NAMESPACE" "$PLAIN_NAMESPACE" --ignore-not-found --wait=false >/dev/null
}

# SHA-256 fingerprint of every certificate of a PEM file, one per line.
pem_fingerprints() {
  local pem="$1" dir cert
  dir="$(mktemp -d -p "$BATS_TEST_TMPDIR")"
  awk -v dir="$dir" '/-----BEGIN CERTIFICATE-----/ { n++ } n { print > (dir "/cert-" n ".pem") }' "$pem"
  for cert in "$dir"/cert-*.pem; do
    [ -e "$cert" ] || continue
    openssl x509 -in "$cert" -noout -fingerprint -sha256 | cut -d= -f2
  done
}

# Creates a namespace (idempotent), labelled as a workload namespace when $2 is "workload".
ensure_namespace() {
  local name="$1" tier="${2:-}"
  kubectl get namespace "$name" >/dev/null 2>&1 || kubectl create namespace "$name" >/dev/null
  if [ "$tier" = workload ]; then
    kubectl label namespace "$name" --overwrite "$WORKLOAD_LABEL_KEY=$WORKLOAD_LABEL_VALUE" >/dev/null
  fi
}

# Waits for the trust bundle ConfigMap in a namespace; writes its JSON to $2.
wait_for_bundle_configmap() {
  local namespace="$1" out="$2" deadline=$((SECONDS + SYNC_TIMEOUT_SECONDS))
  until kubectl -n "$namespace" get configmap "$TRUST_BUNDLE" -o json >"$out" 2>/dev/null; do
    [ "$SECONDS" -lt "$deadline" ] ||
      fail "ConfigMap $namespace/$TRUST_BUNDLE not written within ${SYNC_TIMEOUT_SECONDS}s"
    sleep 5
  done
}

@test "trust-manager is deployed by Argo CD with a bundle of the local CA public certificate" {
  run kubectl -n argocd get applications.argoproj.io "$TRUST_APPLICATION" -o json
  [ "$status" -eq 0 ] || fail "Argo CD Application $TRUST_APPLICATION not found: $output"
  app="$output"
  [ "$(jq -r '.status.sync.status + " " + .status.health.status' <<<"$app")" = "Synced Healthy" ] ||
    fail "Application $TRUST_APPLICATION is not Synced and Healthy: $(jq -c '{sync: .status.sync.status, health: .status.health.status}' <<<"$app")"
  jq -e '[.spec.source, (.spec.sources // [])[]] | map(select(. != null) | .chart) | index("trust-manager") != null' \
    <<<"$app" >/dev/null || fail "Application $TRUST_APPLICATION does not install the trust-manager chart"

  bundle="$(kubectl get bundles.trust.cert-manager.io "$TRUST_BUNDLE" -o json 2>/dev/null ||
    kubectl get clusterbundles.trust-manager.io "$TRUST_BUNDLE" -o json 2>/dev/null)" ||
    fail "no Bundle (or ClusterBundle) $TRUST_BUNDLE in the cluster"
  jq -e '[.spec | .. | strings] | index("tls.key") == null' <<<"$bundle" >/dev/null ||
    fail "Bundle $TRUST_BUNDLE references the CA private key tls.key"
  jq -e '[.spec | .. | objects | select(.includeAllKeys == true)] | length == 0' <<<"$bundle" >/dev/null ||
    fail "Bundle $TRUST_BUNDLE reads every key of a source (includeAllKeys), which would take the CA private key"
}

@test "local CA bundle reaches workload namespaces as PEM and PKCS#12" {
  gateway_ca_fingerprint="$(kubectl -n "$GATEWAY_TLS_NAMESPACE" get secret "$GATEWAY_TLS_SECRET" -o jsonpath='{.data.ca\.crt}' |
    base64 -d | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)"
  [ "$gateway_ca_fingerprint" = "$LOCAL_CA_FINGERPRINT" ] ||
    fail "the platform endpoint certificate is not issued by $CA_NAMESPACE/$CA_SECRET ($gateway_ca_fingerprint != $LOCAL_CA_FINGERPRINT)"

  ensure_namespace "$WORKLOAD_NAMESPACE" workload
  wait_for_bundle_configmap "$WORKLOAD_NAMESPACE" "$BATS_TEST_TMPDIR/configmap.json"

  jq -r --arg k "$PEM_KEY" '.data[$k] // empty' "$BATS_TEST_TMPDIR/configmap.json" >"$BATS_TEST_TMPDIR/bundle.pem"
  [ -s "$BATS_TEST_TMPDIR/bundle.pem" ] || fail "ConfigMap $WORKLOAD_NAMESPACE/$TRUST_BUNDLE has no data key $PEM_KEY"
  ! grep -q 'PRIVATE KEY' "$BATS_TEST_TMPDIR/bundle.pem" ||
    fail "ConfigMap $WORKLOAD_NAMESPACE/$TRUST_BUNDLE key $PEM_KEY holds a private key"
  pem_fingerprints "$BATS_TEST_TMPDIR/bundle.pem" | grep -qxF "$LOCAL_CA_FINGERPRINT" ||
    fail "PEM bundle $PEM_KEY does not contain the local CA $LOCAL_CA_FINGERPRINT"

  jq -r --arg k "$PKCS12_KEY" '.binaryData[$k] // .data[$k] // empty' "$BATS_TEST_TMPDIR/configmap.json" |
    base64 -d >"$BATS_TEST_TMPDIR/bundle.p12"
  [ -s "$BATS_TEST_TMPDIR/bundle.p12" ] || fail "ConfigMap $WORKLOAD_NAMESPACE/$TRUST_BUNDLE has no key $PKCS12_KEY"
  openssl pkcs12 -legacy -in "$BATS_TEST_TMPDIR/bundle.p12" -nokeys -passin pass: \
    -out "$BATS_TEST_TMPDIR/bundle-p12.pem" 2>"$BATS_TEST_TMPDIR/pkcs12.err" ||
    fail "$PKCS12_KEY is not a password-less PKCS#12 trust store: $(cat "$BATS_TEST_TMPDIR/pkcs12.err")"
  pem_fingerprints "$BATS_TEST_TMPDIR/bundle-p12.pem" | grep -qxF "$LOCAL_CA_FINGERPRINT" ||
    fail "PKCS#12 bundle $PKCS12_KEY does not contain the local CA $LOCAL_CA_FINGERPRINT"

  code="$(curl -sS --cacert "$BATS_TEST_TMPDIR/bundle.pem" -o /dev/null -w '%{http_code}' \
    "https://$HARBOR_HOST/api/v2.0/ping")"
  [ "$code" = 200 ] || fail "the PEM bundle does not let a client trust https://$HARBOR_HOST (HTTP $code)"
}

@test "local CA bundle is not written to namespaces without the workload label" {
  ensure_namespace "$PLAIN_NAMESPACE"
  ensure_namespace "$WORKLOAD_NAMESPACE" workload
  # The labelled namespace receiving its copy shows trust-manager has reconciled both namespaces.
  wait_for_bundle_configmap "$WORKLOAD_NAMESPACE" "$BATS_TEST_TMPDIR/configmap.json"

  run kubectl -n "$PLAIN_NAMESPACE" get configmap "$TRUST_BUNDLE" -o name
  [ "$status" -ne 0 ] || fail "ConfigMap $PLAIN_NAMESPACE/$TRUST_BUNDLE exists in a namespace without $WORKLOAD_LABEL_KEY=$WORKLOAD_LABEL_VALUE"

  labelled="$(kubectl get namespaces -l "$WORKLOAD_LABEL_KEY=$WORKLOAD_LABEL_VALUE" -o jsonpath='{.items[*].metadata.name}')"
  run kubectl get configmaps -A --field-selector "metadata.name=$TRUST_BUNDLE" -o jsonpath='{range .items[*]}{.metadata.namespace}{"\n"}{end}'
  [ "$status" -eq 0 ] || fail "cannot list ConfigMaps $TRUST_BUNDLE: $output"
  for namespace in $output; do
    [[ " $labelled " == *" $namespace "* ]] ||
      fail "ConfigMap $namespace/$TRUST_BUNDLE exists in a namespace without $WORKLOAD_LABEL_KEY=$WORKLOAD_LABEL_VALUE"
  done
}

@test "the local CA certificate carries CA basic constraints and certificate signing key usage" {
  # Public certificate only: strict X.509 clients (Python 3.13 VERIFY_X509_STRICT) require both extensions.
  text="$(openssl x509 -in "$LOCAL_CA" -noout -text)"
  grep -A1 'X509v3 Basic Constraints: critical' <<<"$text" | grep -q 'CA:TRUE' ||
    fail "the local CA (Secret $CA_NAMESPACE/$CA_SECRET) has no critical basicConstraints CA:TRUE"
  usage="$(grep -A1 'X509v3 Key Usage: critical' <<<"$text" | tail -n 1 || true)"
  grep -q 'Certificate Sign' <<<"$usage" && grep -q 'CRL Sign' <<<"$usage" ||
    fail "the local CA (Secret $CA_NAMESPACE/$CA_SECRET) has no critical keyUsage keyCertSign, cRLSign (got: ${usage:-none})"
}
