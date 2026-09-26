#!/usr/bin/env bats
# Golden-path apps live on the kind platform: deployed by Argo CD into workload namespaces, admitted by
# the live Kyverno workload policies on their Harbor digest, trusting the local CA delivered at runtime.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
PLATFORM_KUBECONFIG="$REPO_ROOT/.kube/harborlab.yaml"
CATALOG=images/catalog.yaml
HARBOR_HOST=harbor.127.0.0.1.nip.io
APPS_PROJECT=apps
GHCR_APPS=ghcr.io/naqa92-portfolio-projects/harborlab/apps
WORKLOAD_LABEL=harborlab.io/tier=workload
PSA_LABEL=pod-security.kubernetes.io/enforce
TRUST_BUNDLE=harborlab-trust
TRUST_MOUNT=/etc/harborlab-trust
CA_NAMESPACE=cert-manager
CA_SECRET=harborlab-ca
APP_PORT=8080
OIDC_ISSUER=https://token.actions.githubusercontent.com
BUILD_IDENTITY='^https://github\.com/naqa92-portfolio-projects/harborlab/\.github/workflows/build-image\.yml@refs/heads/(main|prd-.+)$'
WORKLOAD_POLICIES=(workload-image-signature workload-golden-base workload-golden-base-deprecated workload-image-labels workload-registry)
REPORT_TIMEOUT_SECONDS=150

fail() {
  echo "$*" >&2
  return 1
}

setup_file() {
  [ -s "$PLATFORM_KUBECONFIG" ] || fail "platform is not up: $PLATFORM_KUBECONFIG missing (run task up)"
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  kubectl -n gateway get secret wildcard-nip-io-tls -o jsonpath='{.data.ca\.crt}' | base64 -d \
    >"$BATS_FILE_TMPDIR/harbor-ca.crt"
  [ -s "$BATS_FILE_TMPDIR/harbor-ca.crt" ] || fail "Secret gateway/wildcard-nip-io-tls has no ca.crt"
  kubectl -n "$CA_NAMESPACE" get secret "$CA_SECRET" -o jsonpath='{.data.tls\.crt}' | base64 -d \
    >"$BATS_FILE_TMPDIR/local-ca.crt"
  [ -s "$BATS_FILE_TMPDIR/local-ca.crt" ] || fail "Secret $CA_NAMESPACE/$CA_SECRET has no tls.crt"
}

setup() {
  export KUBECONFIG="$PLATFORM_KUBECONFIG"
  HARBOR_CA="$BATS_FILE_TMPDIR/harbor-ca.crt"
  LOCAL_CA_SHA256="$(openssl x509 -in "$BATS_FILE_TMPDIR/local-ca.crt" -noout -fingerprint -sha256 |
    cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
  [ -n "$LOCAL_CA_SHA256" ] || fail "tls.crt of Secret $CA_NAMESPACE/$CA_SECRET is not a certificate"
}

# Argo CD Application $1 is Synced and Healthy and manages the Deployment $1 in namespace $1, a workload
# namespace under Pod Security restricted; the Deployment is fully available. Sets APP_PODS (names of
# its Ready pods) and writes their JSON to $BATS_TEST_TMPDIR/pods.json.
assert_deployed_by_argocd() {
  local app="$1" namespace="$1" application deployment selector
  application="$(kubectl -n argocd get applications.argoproj.io "$app" -o json 2>&1)" ||
    fail "Argo CD Application $app not found: $application"
  [ "$(jq -r '.status.sync.status + " " + .status.health.status' <<<"$application")" = "Synced Healthy" ] ||
    fail "Application $app is not Synced and Healthy: $(jq -c '{sync: .status.sync.status, health: .status.health.status}' <<<"$application")"
  jq -e --arg ns "$namespace" --arg name "$app" \
    'any(.status.resources[]?; .group == "apps" and .kind == "Deployment" and .namespace == $ns and .name == $name)' \
    <<<"$application" >/dev/null ||
    fail "Application $app does not manage Deployment $namespace/$app: $(jq -c '[.status.resources[]? | {kind, namespace, name}]' <<<"$application")"

  [ "$(kubectl get namespace "$namespace" -o jsonpath="{.metadata.labels.harborlab\.io/tier}")" = workload ] ||
    fail "namespace $namespace is not labelled $WORKLOAD_LABEL"
  [ "$(kubectl get namespace "$namespace" -o jsonpath="{.metadata.labels.pod-security\.kubernetes\.io/enforce}")" = restricted ] ||
    fail "namespace $namespace does not enforce Pod Security restricted ($PSA_LABEL)"

  deployment="$(kubectl -n "$namespace" get deployment "$app" -o json 2>&1)" ||
    fail "Deployment $namespace/$app not found: $deployment"
  jq -e '(.spec.replicas // 1) >= 1 and (.status.availableReplicas // 0) == (.spec.replicas // 1)
      and (.status.updatedReplicas // 0) == (.spec.replicas // 1)' <<<"$deployment" >/dev/null ||
    fail "Deployment $namespace/$app is not fully available: $(jq -c '.status | {replicas, availableReplicas, updatedReplicas, conditions}' <<<"$deployment")"

  selector="$(jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")' <<<"$deployment")"
  kubectl -n "$namespace" get pods -l "$selector" -o json >"$BATS_TEST_TMPDIR/pods.json"
  mapfile -t APP_PODS < <(jq -r '.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name' \
    "$BATS_TEST_TMPDIR/pods.json")
  [ "${#APP_PODS[@]}" -ge 1 ] || fail "Deployment $namespace/$app has no pod"
  jq -e '[.items[] | select(.metadata.deletionTimestamp == null)]
      | all(.[]; .status.phase == "Running" and any(.status.conditions[]?; .type == "Ready" and .status == "True"))' \
    "$BATS_TEST_TMPDIR/pods.json" >/dev/null ||
    fail "pods of Deployment $namespace/$app are not all Running and Ready: $(jq -c '[.items[] | {name: .metadata.name, phase: .status.phase, containers: [.status.containerStatuses[]? | {name, ready, state}]}]' "$BATS_TEST_TMPDIR/pods.json")"
}

# Every container of the app's pods runs a digest reference of the platform registry, the app container
# its Harbor `apps` image. Sets APP_DIGEST (the app container's digest, identical across pods).
assert_harbor_digest_images() {
  local app="$1" pattern digests
  jq -e '[.items[].spec | (.initContainers // []) + .containers | .[].image]
      | all(.[]; test("^harbor\\.127\\.0\\.0\\.1\\.nip\\.io/(apps|golden)/[^@]+@sha256:[0-9a-f]{64}$"))' \
    "$BATS_TEST_TMPDIR/pods.json" >/dev/null ||
    fail "a pod of $app runs an image that is not a Harbor golden/apps digest reference: $(jq -c '[.items[].spec | (.initContainers // []) + .containers | .[].image]' "$BATS_TEST_TMPDIR/pods.json")"
  pattern="^harbor\\.127\\.0\\.0\\.1\\.nip\\.io/apps/$app(:[^@/]+)?@(sha256:[0-9a-f]{64})$"
  mapfile -t digests < <(jq -r --arg c "$app" '.items[].spec.containers[] | select(.name == $c) | .image' \
    "$BATS_TEST_TMPDIR/pods.json" | sed -nE "s#$pattern#\\2#p" | sort -u)
  [ "${#digests[@]}" -eq 1 ] ||
    fail "container $app of the $app pods does not run one $HARBOR_HOST/$APPS_PROJECT/$app@sha256 image: $(jq -c --arg c "$app" '[.items[].spec.containers[] | select(.name == $c) | .image]' "$BATS_TEST_TMPDIR/pods.json")"
  APP_DIGEST="${digests[0]}"
}

# The Harbor reference $1 verifies against the build-image.yml identity and its SLSA provenance names
# exactly one base, a supported entry of the golden catalog.
assert_harbor_image_verifies() {
  local ref="$1" err="$BATS_TEST_TMPDIR/cosign.err" bases status
  local args=(--certificate-oidc-issuer "$OIDC_ISSUER" --certificate-identity-regexp "$BUILD_IDENTITY"
    --registry-cacert "$HARBOR_CA")
  cosign verify "${args[@]}" "$ref" >/dev/null 2>"$err" ||
    fail "cosign verify failed on $ref against $BUILD_IDENTITY: $(tail -n 5 "$err")"
  cosign verify-attestation "${args[@]}" --type slsaprovenance1 "$ref" >"$BATS_TEST_TMPDIR/slsa.json" 2>"$err" ||
    fail "SLSA provenance of $ref not verified against $BUILD_IDENTITY: $(tail -n 5 "$err")"
  mapfile -t bases < <(jq -rs '[.[].payload | @base64d | fromjson | .predicate.buildDefinition.resolvedDependencies[]?
      | select((.uri // "") | startswith("oci://")) | .digest.sha256 // ""] | unique[]' "$BATS_TEST_TMPDIR/slsa.json")
  [ "${#bases[@]}" -eq 1 ] || fail "SLSA provenance of $ref records ${#bases[@]} oci:// base(s), expected one: ${bases[*]}"
  status="$(yq -r ".images[] | select(.digest == \"sha256:${bases[0]}\") | .status" "$REPO_ROOT/$CATALOG" | sort -u)"
  [ "$status" = supported ] ||
    fail "the base sha256:${bases[0]} of $ref is not a supported entry of $CATALOG (status: '${status:-absent}')"
}

# The PolicyReport of each app pod holds a pass from every workload policy and no other result of them.
assert_admission_reports() {
  local namespace="$1" pod policy results deadline
  for pod in "${APP_PODS[@]}"; do
    deadline=$((SECONDS + REPORT_TIMEOUT_SECONDS))
    while :; do
      results="$(kubectl -n "$namespace" get policyreports.wgpolicyk8s.io -o json |
        jq -c --arg pod "$pod" '[.items[] | select(.scope.kind == "Pod" and .scope.name == $pod) | .results[]?
          | select(.policy | startswith("workload-")) | {policy, result}] | unique')"
      missing=""
      for policy in "${WORKLOAD_POLICIES[@]}"; do
        jq -e --arg p "$policy" 'any(.[]; .policy == $p and .result == "pass")' <<<"$results" >/dev/null ||
          missing+="$policy "
      done
      [ -n "$missing" ] || break
      [ "$SECONDS" -lt "$deadline" ] ||
        fail "PolicyReport of pod $namespace/$pod has no pass from: $missing(results: $results)"
      sleep 10
    done
    jq -e 'all(.[]; .result == "pass")' <<<"$results" >/dev/null ||
      fail "PolicyReport of pod $namespace/$pod holds non-pass workload results: $results"
  done
}

# A restricted pod on image $2, server dry-run in namespace $1: goes through the live admission chain.
dry_run_pod() {
  kubectl -n "$1" create --dry-run=server -o name -f - 2>&1 <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: admission-probe
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: $2
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
EOF
}

# Live admission now: the app's Harbor digest is admitted without warning in its namespace, and the same
# digest served from GHCR is denied by the workload registry policy (control: the policies enforce there).
assert_live_admission() {
  local namespace="$1" app="$2" digest="$3"
  run dry_run_pod "$namespace" "$HARBOR_HOST/$APPS_PROJECT/$app@$digest"
  [ "$status" -eq 0 ] || fail "live admission denies $HARBOR_HOST/$APPS_PROJECT/$app@$digest in $namespace: $output"
  [[ "$output" != *Warning* ]] || fail "live admission warns on $HARBOR_HOST/$APPS_PROJECT/$app@$digest in $namespace: $output"
  run dry_run_pod "$namespace" "$GHCR_APPS/$app@$digest"
  [ "$status" -ne 0 ] || fail "control: live admission admits the GHCR reference of $app in $namespace"
  [[ "$output" == *workload-registry* ]] ||
    fail "control: the GHCR reference of $app is not denied by workload-registry in $namespace: $output"
}

# Container $2 of Deployment $1 (namespace $1) mounts ConfigMap harborlab-trust at /etc/harborlab-trust.
assert_trust_bundle_mounted() {
  local app="$1" container="$2"
  jq -e --arg c "$container" --arg cm "$TRUST_BUNDLE" --arg path "$TRUST_MOUNT" '
      all(.items[].spec; . as $spec | [$spec.volumes[]? | select(.configMap.name == $cm) | .name] as $vols
        | any($spec.containers[] | select(.name == $c) | .volumeMounts[]?;
            (.name as $n | $vols | index($n) != null) and .mountPath == $path and (.subPath // "") == ""))' \
    "$BATS_TEST_TMPDIR/pods.json" >/dev/null ||
    fail "container $container of the $app pods does not mount ConfigMap $TRUST_BUNDLE at $TRUST_MOUNT"
}

@test "dt-bridge runs admitted in a workload namespace, deployed by ArgoCD" {
  app=dt-bridge
  assert_deployed_by_argocd "$app"
  assert_harbor_digest_images "$app"
  assert_harbor_image_verifies "$HARBOR_HOST/$APPS_PROJECT/$app@$APP_DIGEST"
  assert_admission_reports "$app"
  assert_live_admission "$app" "$app" "$APP_DIGEST"

  run kubectl get --raw "/api/v1/namespaces/$app/services/http:$app:$APP_PORT/proxy/healthz"
  [ "$status" -eq 0 ] || fail "GET /healthz on Service $app/$app:$APP_PORT failed: $output"
  jq -e '.status == "ok"' <<<"$output" >/dev/null || fail "GET /healthz on dt-bridge did not answer {\"status\": \"ok\"}: $output"

  # Python trusts the local CA from the bundle alone: the golden image bakes no CA.
  assert_trust_bundle_mounted "$app" "$app"
  jq -e --arg c "$app" --arg f "$TRUST_MOUNT/ca.crt" \
    'all(.items[].spec.containers[] | select(.name == $c); any(.env[]?; .name == "SSL_CERT_FILE" and .value == $f))' \
    "$BATS_TEST_TMPDIR/pods.json" >/dev/null || fail "container $app does not set SSL_CERT_FILE=$TRUST_MOUNT/ca.crt"
  run kubectl -n "$app" exec "${APP_PODS[0]}" -c "$app" -- python -c \
    'import hashlib, ssl; print("\n".join(hashlib.sha256(c).hexdigest() for c in ssl.create_default_context().get_ca_certs(binary_form=True)))'
  [ "$status" -eq 0 ] || fail "cannot list the CAs of Python's default TLS context in $app/${APP_PODS[0]}: $output"
  grep -qxF "$LOCAL_CA_SHA256" <<<"$output" ||
    fail "Python's default TLS context in $app/${APP_PODS[0]} does not trust the local CA (sha256 $LOCAL_CA_SHA256)"
}

@test "hello-java runs admitted in a workload namespace, deployed by ArgoCD" {
  app=hello-java
  assert_deployed_by_argocd "$app"
  assert_harbor_digest_images "$app"
  assert_harbor_image_verifies "$HARBOR_HOST/$APPS_PROJECT/$app@$APP_DIGEST"
  assert_admission_reports "$app"
  assert_live_admission "$app" "$app" "$APP_DIGEST"

  run kubectl get --raw "/api/v1/namespaces/$app/services/http:$app:$APP_PORT/proxy/"
  [ "$status" -eq 0 ] && [ -n "$output" ] || fail "GET / on Service $app/$app:$APP_PORT failed: $output"

  # The JVM takes the PKCS#12 trust store of the bundle as its default trust store.
  assert_trust_bundle_mounted "$app" "$app"
  run kubectl -n "$app" exec "${APP_PODS[0]}" -c "$app" -- java -XshowSettings:properties -version
  [ "$status" -eq 0 ] || fail "cannot read the JVM properties in $app/${APP_PODS[0]}: $output"
  grep -qE "^[[:space:]]*javax\.net\.ssl\.trustStore = $TRUST_MOUNT/truststore\.p12[[:space:]]*$" <<<"$output" ||
    fail "the JVM in $app/${APP_PODS[0]} does not use $TRUST_MOUNT/truststore.p12 as trust store: $(grep -i 'javax.net.ssl' <<<"$output")"
  grep -qiE '^[[:space:]]*javax\.net\.ssl\.trustStoreType = PKCS12[[:space:]]*$' <<<"$output" ||
    fail "the JVM in $app/${APP_PODS[0]} does not read its trust store as PKCS12: $(grep -i 'javax.net.ssl' <<<"$output")"
}
