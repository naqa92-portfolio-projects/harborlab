# Test catalog — PRD #1 harborlab: Image Governance Platform

One row per acceptance criterion (`CAT-<nn>` = criterion `nn`), plus `CAT-000` for the M0 spike and
`CAT-D<nn>` for a decision proven on its own (`CAT-D04`: Decision 4, runtime CA via trust-manager).
Every path below is repo-relative. The repo had no tests when this catalog was written, so the
conventions below are chosen for the PRD's stack.

## Conventions

| Family | Location | Runner (single test) | Where it runs |
|---|---|---|---|
| Repo / CI / docs checks (unit) | `tests/ci/*.bats`, `tests/docs/*.bats` | `devbox run -- bats <file> -f '<name>'` | GitHub Actions + local |
| Kyverno policy unit tests | `tests/kyverno/<tier>/<policy>/kyverno-test.yaml`, one policy per suite (+ tier-shared `tests/kyverno/<tier>/{resources/,values.yaml,context.yaml}`) | `devbox run -- tests/kyverno/run.sh [<tier>/<policy>…]` (pins fixture tags, fetches image metadata, then `kyverno test --registry`) | GitHub Actions + local |
| Admission E2E | `tests/chainsaw/<suite>/<case>/chainsaw-test.yaml` | `devbox run -- chainsaw test --test-dir tests/chainsaw/<suite>/<case>` on a kind cluster with Kyverno, `policies/{workload,platform}` and `tests/chainsaw/params` applied | ephemeral kind in GitHub Actions |
| Platform live tests | `tests/platform/*.bats` | `devbox run -- bats <file> -f '<name>'` | local kind platform (`task up`) |
| Supply-chain live tests | `tests/supply-chain/*.bats` | `devbox run -- bats <file> -f '<name>'` | GHCR + local Harbor |
| M0 spike live tests | `tests/spike/*.bats` | `devbox run -- bats <file> -f '<name>'` | spike kind cluster |
| dt-bridge unit tests | `apps/dt-bridge/tests/test_*.py` (fixtures in `apps/dt-bridge/tests/fixtures/`) | `cd apps/dt-bridge && uv run pytest <file>::<test>` | GitHub Actions + local |

Assumptions (update the File column if the implementation lands elsewhere): apps live in
`apps/dt-bridge` and `apps/hello-java`; the Harbor host is `harbor.127.0.0.1.nip.io`; lint checks
are exposed as tasks that accept a target path so a test can point them at a temp directory.

M0 spike interface assumed by `tests/spike/m0.bats` (CAT-000):
- `spike/up.sh` (executable, idempotent, prints no secret) creates or converges the kind cluster
  `harborlab-spike`; the test calls it once per run and reads the kubeconfig with
  `kind get kubeconfig`, never from the repository.
- Harbor at `https://harbor.127.0.0.1.nip.io`, reachable from the host; its CA PEM in Secret
  `harbor/harbor-ca` key `ca.crt`; admin password in Secret `harbor/harbor-core` key
  `HARBOR_ADMIN_PASSWORD` (user `admin`); Harbor workloads are the Deployments and StatefulSets of
  namespace `harbor`.
- `.github/workflows/spike.yml` publishes the public image
  `ghcr.io/naqa92-portfolio-projects/harborlab/spike/hello:m0`, keyless-signed and attested
  (`cyclonedx`, `spdxjson`, `slsaprovenance1`); Harbor public project `spike` holds it as
  `spike/hello:m0` (replicated, same digest) and an unsigned image `spike/unsigned:m0`.
- Kyverno ImageValidatingPolicy `spike-verify-harbor` enforces the spike identity on
  `harbor.127.0.0.1.nip.io/spike/*` in namespaces labelled `harborlab.io/tier=workload` only.
- The kind node's containerd mirrors `docker.io` to the public Harbor proxy-cache project
  `dockerhub-proxy`, with `registry-1.docker.io` as fallback.
- Tools on the devbox PATH: `bats`, `kind`, `kubectl`, `cosign` (with `--registry-cacert`),
  `crane`, `jq`, `curl`, `docker`.

M1 interface assumed by `tests/platform/lifecycle.bats` (CAT-001, CAT-002),
`tests/platform/secrets.bats` and `tests/ci/secrets.bats` (CAT-024):
- Devbox provides `task` (go-task) and `gitleaks` on the `devbox run` PATH, in addition to the M0
  tools. `Taskfile.yml` at the repository root defines `up` and `down`; the tests run them from
  the repository root, which is what `devbox run -- task up|down` does.
- `task up` creates or converges the kind cluster `harborlab` (distinct from `harborlab-spike`;
  if both publish `127.0.0.1:443`, the spike must be down first — the tests do not manage it) and
  exits 0 only after every `applications.argoproj.io` has been `Synced` and `Healthy` for 60
  consecutive seconds. Every Application uses automated sync, so each has
  `status.operationState` (`phase: Succeeded`, `finishedAt`) and `status.health.lastTransitionTime`
  (health persisted in the Application CR, the ArgoCD default). The Applications `root`
  (app-of-apps), `cert-manager`, `openbao`, `external-secrets` and `cloudnative-pg` exist; any other
  Application is allowed and must converge too.
- Isolated kubeconfig: `task up` writes `.kube/harborlab.yaml` (repo-relative, mode 600,
  git-ignored, current context `kind-harborlab`) and leaves `$HOME/.kube/config` byte-for-byte
  unchanged; `task down` deletes the cluster and that file, and leaves `$HOME/.kube/config`
  unchanged. Neither task prints the `DHI_TOKEN` value.
- OpenBao: pod `openbao-0`, container `openbao`, namespace `openbao`, initialized and unsealed;
  its `bao` CLI reaches the server with the container's preset environment. KV v2 engine mounted
  at `secret/`; platform credentials live under `secret/platform/<name>`. Kubernetes auth mounted
  at `kubernetes/` with role `platform-audit` bound to ServiceAccount `openbao/platform-audit`,
  policy limited to `read` on `secret/data/platform/*` and `read` on `sys/mounts`. The test logs in
  with a short-lived token of that ServiceAccount (`kubectl create token`), passed on stdin.
- External Secrets: ClusterSecretStore `openbao` is `Ready`, provider `vault` with `path: secret`,
  `version: v2` and `auth.kubernetes`; every ExternalSecret in the cluster is `Ready`. Each
  credential Secret is controller-owned by an ExternalSecret using `ClusterSecretStore/openbao` whose
  `remoteRef.key` (or `dataFrom.extract.key`) is its `platform/<name>` path.
- Credential table `PLATFORM_CREDENTIALS` in `tests/platform/secrets.bats`, one line
  `<kv path>|<field>|<namespace>/<Secret>|<key>` per credential. Empty at M1 (the mechanism alone
  is asserted: unseal, KV v2 mount, Kubernetes-auth login, store Ready); M2 adds Harbor admin,
  robots, the Harbor DB and the DHI pull token, M6 the DT API key, admin password and DB, and dt-bridge's robot and DHI Secrets.
- `tests/ci/secrets.bats` needs the full history (no shallow clone) and reads `DHI_TOKEN` from the
  environment of `devbox run`; the value is a grep pattern read from stdin, never in argv or
  output. A `.gitleaks.toml` at the repository root is used when present.

M2 interface assumed by `tests/platform/harbor_configure.bats` (CAT-003; its state test also CAT-024),
`tests/platform/registry_mirror.bats` (CAT-004) and the M2 lines of `PLATFORM_CREDENTIALS` in
`tests/platform/secrets.bats` (CAT-024):
- Deployment: ArgoCD Application `harbor` (Synced, Healthy; `task up` still converges), Helm
  release `harbor` in namespace `harbor`, workloads labelled `app=harbor` (chart default). Database:
  CNPG Cluster `harbor/harbor-db`, `instances: 1`, phase `Cluster in healthy state`,
  `bootstrap.initdb.secret.name: harbor-db-credentials`; ConfigMap `harbor/harbor-core` key
  `POSTGRESQL_HOST` is `harbor-db-rw` (or its FQDN).
- Endpoint: `https://harbor.127.0.0.1.nip.io` through the Cilium Gateway; tests trust the CA in
  Secret `gateway/wildcard-nip-io-tls` key `ca.crt`. Admin user `admin`, password in Secret
  `harbor/harbor-admin` key `HARBOR_ADMIN_PASSWORD` (chart `existingSecretAdminPassword`); the chart's
  own `harbor-core` Secret is no longer read by tests.
- Credentials (OpenBao KV v2 → ExternalSecret through `ClusterSecretStore/openbao`), seeded once by
  `task up` and never overwritten, except robots written by `task harbor:configure`; the DHI entry
  is seeded from the `DHI_TOKEN` environment variable (never from a tracked file):
  | OpenBao path | Fields | Kubernetes Secret (keys) |
  |---|---|---|
  | `secret/platform/harbor-admin` | `password` | `harbor/harbor-admin` (`HARBOR_ADMIN_PASSWORD`) |
  | `secret/platform/harbor-db` | `username`, `password` | `harbor/harbor-db-credentials` (`username`, `password`, type `kubernetes.io/basic-auth`) |
  | `secret/platform/harbor-robot-dt-bridge` | `username` (= `robot$dt-bridge`), `password` | `dt-bridge/harbor-robot-dt-bridge` (`username`, `password`) from M6 (none before) |
  | `secret/platform/dhi` | `username` (Docker account owning the token), `token` (= `DHI_TOKEN`) | `registry-mirror-test/dhi-pull` (`.dockerconfigjson`, type `kubernetes.io/dockerconfigjson`, `auths["dhi.io"]` with `auth` or `password` set), controller-owned by ExternalSecret `registry-mirror-test/dhi-pull` reading `platform/dhi`; `task harbor:configure` also reads it for the `dhi` registry endpoint |
- Harbor configuration is OpenTofu (Decision 8): Devbox provides `tofu` (a release with
  write-only attributes and ephemeral resources); the root module is `tofu/harbor/` (not under
  `platform/harbor/`, an Argo CD directory source), with providers `goharbor/harbor` (a release
  whose `harbor_robot_account` has `secret_wo`) and `hashicorp/vault` pointed at OpenBao. Every
  category is a managed resource of that state: `harbor_project` (proxy caches and governed
  projects, `deployment_security` and `vulnerability_scanning` on `golden`/`apps`),
  `harbor_registry`, `harbor_replication`, `harbor_robot_account`, `harbor_immutable_tag_rule`,
  `harbor_retention_policy`, `harbor_project_webhook`; per-project resources reference the project
  by its `harbor_project.<x>.id` (`project_id`, or `scope` for retention). A first run on a Harbor
  already configured by an earlier tool adopts the existing objects instead of failing.
- State: local backend at `tofu/harbor/terraform.tfstate` (and `.backup` when present),
  git-ignored and untracked, encrypted with an `encryption` block whose key provider is
  `openbao` (OpenBao Transit engine mounted at `transit/`, key `harbor-tofu-state`, no
  `encrypted_metadata_alias`, so the payload's `meta` holds `key_provider.openbao.<name>`), state
  encryption enforced. The file on disk is an OpenTofu encrypted payload (`encrypted_data`,
  `encryption_version`, no readable `resources`) and contains neither the admin password, a robot
  secret nor the DHI token. The `dhi` registry `access_secret` has no write-only variant and is
  the one secret the decrypted state may hold.
- Tasks (Taskfile, run from the repository root under `devbox run`; none prints the admin
  password, a robot secret or the DHI token, on stdout or stderr):
  - `task harbor:configure`: seeds missing robot secrets in OpenBao, then `tofu init` + `tofu apply`
    (non-interactive); exits 0 on success, including on an already configured Harbor.
  - `task harbor:plan`: `tofu plan -detailed-exitcode` on the same configuration and inputs; exits
    0 only when the plan is empty, non-zero when changes are pending or on error.
  - `task harbor:tofu -- <args>`: runs `tofu <args>` in `tofu/harbor/` with the same provider and
    encryption environment; its stdout is tofu's stdout only, so `task harbor:tofu -- show -json`
    prints the decrypted state as JSON (tests write it to a mode-600 temp file, never print it).
- A run on a configured Harbor changes nothing in the admin API (projects + metadata, registries,
  replication policies, robots, immutable rules, retention policies, webhook policies;
  `creation_time`, `update_time`, `repo_count`, `chart_count`, `status` ignored, robot permissions
  and access compared as sets) nor the KV version of a robot path.
- Proxy caches, public projects, one registry endpoint each:
  | Project | Endpoint name | Type | URL |
  |---|---|---|---|
  | `dockerhub-proxy` | `dockerhub` | `docker-hub` | `https://hub.docker.com` |
  | `quay-proxy` | `quay` | `quay` | `https://quay.io` |
  | `ghcr-proxy` | `ghcr` | `github-ghcr` | `https://ghcr.io` |
  | `k8s-proxy` | `k8s` | `docker-registry` | `https://registry.k8s.io` |
  | `dhi-proxy` | `dhi` | `docker-registry` | `https://dhi.io` (credential held by Harbor, from OpenBao `secret/platform/dhi`) |
- Governed projects `golden` and `apps`: public, not proxy caches, and each has
  - deployment security: metadata `prevent_vul=true`, `severity=critical`, `auto_scan=true`
    (cosign content trust is not required: Sigstore bundles arrive as OCI referrers, ADR 0001);
  - an enabled immutable rule, repositories `**` (`repoMatches`), tags `excludes` `sha256-*` so later
    attestations can update the referrers fallback index;
  - a retention policy with at least one rule and a `Schedule` trigger with a cron;
  - an enabled webhook policy `dt-bridge`, target type `http`, address
    `http://dt-bridge.dt-bridge.svc.cluster.local:8080/harbor/events` (placeholder until M6), event
    types including `PUSH_ARTIFACT` and `REPLICATION`;
  - a pull-replication policy from endpoint `ghcr`: `golden-from-ghcr` (name filter
    `naqa92-portfolio-projects/harborlab/golden/{python,java}`) and `apps-from-ghcr`
    (`naqa92-portfolio-projects/harborlab/apps/{dt-bridge,hello-java}`) — amended in M3: Harbor's
    `github-ghcr` adapter cannot list GHCR repositories and fails every execution of a wildcard name
    filter (`only support specific repository name`, observed on `golden/**`); a specific name or a
    single `{a,b}` list is accepted — enabled, `dest_namespace` the project,
    `dest_namespace_replace_count: -1`, trigger `scheduled`, tag filter absent, `**`, or a `matches`
    brace pattern listing `sha256-*`.
- Robot `robot$dt-bridge`: system level, enabled, `duration: -1`, permissions on exactly `golden`
  and `apps`, actions limited to `pull`, `read`, `list`. Its secret is generated once into OpenBao
  `secret/platform/harbor-robot-dt-bridge` (`password`) and reaches Harbor only as `secret_wo` +
  `secret_wo_version`, read through the ephemeral `vault_kv_secret_v2`; the `harbor_robot_account`
  in the decrypted state has no `secret` value. With that credential (basic auth on stdin),
  `GET https://harbor.127.0.0.1.nip.io/v2/` returns 200; with a wrong secret, 401.
- Mirror test images (layers shared with no platform image, checked against the node's layer set
  captured before the pull): `docker.io/library/busybox:1.36.1`, `quay.io/libpod/busybox:1.30.1`,
  `ghcr.io/containerd/busybox:1.36`, `registry.k8s.io/pause:3.9`, `dhi.io/busybox:1.37.0-debian13`.
  Pods run in namespace `registry-mirror-test`, deployed by the platform (it holds the ExternalSecret
  `dhi-pull`; the test only creates it when absent, and it carries no `harborlab.io/tier=workload`
  label). The dhi.io pods (proxy and fallback) set `imagePullSecrets: [dhi-pull]`: containerd's
  CRI resolver hands pod credentials only to the image reference's host, so the anonymous public
  `dhi-proxy` mirror serves the proxy case and only the `dhi.io` fallback authenticates. The dhi.io
  platform digest is resolved from the index served by `dhi-proxy` (anonymous); the test never
  reads `DHI_TOKEN`.
- Fallback: the test pauses automated sync on Applications `root` then `harbor`, scales the
  `app=harbor` Deployments and StatefulSets to 0 (CNPG pods stay), and restores replicas and sync
  policies in teardown. containerd must fall back upstream when the Gateway has no Harbor backend,
  for all five upstreams including `dhi.io` (authenticated by the pod's `dhi-pull` secret).

M3 interface assumed by `tests/ci/catalog.bats` (CAT-008), `tests/ci/platform_lint.bats` (CAT-014),
`tests/ci/golden_workflow.bats`, `tests/supply-chain/golden_images.bats` (CAT-005) and
`tests/supply-chain/harbor_replicated.bats` (CAT-006, golden part), the last two sharing
`tests/supply-chain/golden.bash`:
- Tools: Devbox provides `yq` (mikefarah v4) in addition to the M0–M2 tools, and whatever the lint
  task runs (zizmor, hadolint, trivy, kube-linter; gitleaks is already there). Live supply-chain tests
  also use the host `gh` (logged in, a PRD prerequisite). CI tests run from any checkout; the lint
  test on the repository needs the full history (gitleaks).
- Catalog `images/catalog.yaml`: top-level `images:` list; each entry has exactly these required
  fields: `name` (golden repository name, `[a-z0-9-]+`, e.g. `python`, `java`), `version` (non-empty
  string), `digest` (`sha256:` + 64 lowercase hex: the golden image manifest digest on GHCR, the
  same in Harbor), `status` (`supported|deprecated|eol`), `released` and `eol` (quoted ISO
  `YYYY-MM-DD` strings naming a real calendar day). Several entries may share a name (versions or
  successive builds). The catalog holds at least one `supported` entry for `python` and one for
  `java`. Fixtures: `tests/fixtures/catalog/valid.yaml` (one entry per status) and one defective
  second entry per invalid fixture (`missing-digest`, `invalid-status`, `malformed-digest`,
  `invalid-date`).
- Tasks (Taskfile, run from the directory holding the Taskfile; a copy of the working tree in a temp
  directory must work the same way, without `.env`):
  - `task catalog:validate [-- <absolute path>]`: validates the given catalog file (default
    `images/catalog.yaml`); exit 0 when valid, non-zero otherwise with an error naming the offending
    field (`digest`, `status`, `eol`, …).
  - `task catalog:generate`: writes, from `images/catalog.yaml`, the Kyverno params ConfigMap
    `policies/params/golden-images.yaml` and the catalog doc `docs/golden-images.md`; deterministic
    (a fresh run on the committed catalog reproduces the committed files byte for byte).
  - `task catalog:check`: exits non-zero when either generated file differs from what
    `catalog:generate` would write, 0 otherwise; it only reports and leaves both files unchanged.
- Params ConfigMap `policies/params/golden-images.yaml`: `kind: ConfigMap`, `metadata.name:
  golden-images`, `metadata.namespace: kyverno`; `data` holds one key per catalog entry,
  `sha256.<64 hex>` (ConfigMap keys cannot hold `:`), whose value is the entry's status. Other keys are
  allowed (M4 may add more). Doc `docs/golden-images.md`: one Markdown table row per entry holding its
  name, version, digest and status (and dates).
- Lint: `task lint` lints the repository root; `task lint -- <absolute dir>` lints `<dir>` as a
  repository root (a git work tree). It runs every check even after one fails, prints one line
  `FAILED <check>` per failing check and exits non-zero iff one failed, with these check ids and
  scopes:
  | Check id | Scope under the target |
  |---|---|
  | `zizmor` | `.github/workflows/*.y*ml` (template injection among the findings that fail) |
  | `pinned-actions` | every `uses:` of those workflows pinned to a 40-hex commit SHA (local `./` and `docker://…@sha256` excepted) |
  | `gitleaks` | the git history of the target |
  | `hadolint` | every Dockerfile, failing on `error` severity at least |
  | `trivy-config` | `trivy config` on the target, failing on HIGH and CRITICAL |
  | `kube-linter` | Kubernetes manifests (e.g. `deploy/*.yaml`) |
  | `from-golden` | every Dockerfile's `FROM` must be `ghcr.io/naqa92-portfolio-projects/harborlab/golden/<name>[:<tag>]@sha256:<digest>` or `harbor.127.0.0.1.nip.io/golden/<name>[:<tag>]@sha256:<digest>` with (`name`, `digest`) a `supported` entry of the target's `images/catalog.yaml` |
  Exclusions: `tests/**` (deliberately non-compliant fixtures) for every file-based check;
  `images/golden/**` (built FROM DHI) and `spike/**` for `from-golden`. The clean fixture the test
  builds (catalog, `apps/hello/Dockerfile` FROM a supported golden digest with `USER 65532:65532`, a
  `permissions: {}` workflow with a SHA-pinned `actions/checkout` and `persist-credentials: false`)
  must pass every check; the `deprecated` case is not asserted.
- Platform CI `.github/workflows/platform-ci.yml`: triggers on `pull_request` with no `paths`,
  `paths-ignore` or `branches` filter; a job without `continue-on-error: true` checks out with
  `actions/checkout` and `fetch-depth: 0` and has blocking steps running `task lint` and
  `task catalog:check` (e.g. `devbox run -- task lint`).
- Golden build `.github/workflows/golden.yml`: `on.push.branches` lists `main` and `on.push.paths`
  lists `images/golden/**`; during the PRD it must also run and publish on the PRD branch (a push
  trigger on that branch and/or `workflow_dispatch`); the images are then signed with the identity of
  that branch (`refs/heads/<branch>`). Sources `images/golden/{python,java}/Dockerfile`, whose first
  `FROM` is a digest-pinned `dhi.io/<repo>[:<tag>]@sha256:<digest>` (Renovate-managed).
  - Publishes `ghcr.io/naqa92-portfolio-projects/harborlab/golden/{python,java}` (public), each run
    tagging its image `sha-<github.sha>` (40 hex); tags are never overwritten (Harbor `golden` tags
    are immutable), so a run that finds its tag present does not push it again.
  - Signs and attests keyless (cosign v3 bundles, ADR 0001) each digest: signature, `cyclonedx`
    (predicate with `components`), `spdxjson` (with `packages`), `slsaprovenance1`, whose
    `buildDefinition.resolvedDependencies` holds the built commit (`digest.gitCommit` = `github.sha`)
    and exactly one `oci://dhi.io/<repo>[:<tag>]` entry with `digest.sha256` = the DHI digest pinned
    in the Dockerfile. Certificate identity
    `https://github.com/naqa92-portfolio-projects/harborlab/.github/workflows/golden.yml@<ref>` (or
    `build-image.yml@<ref>` when golden.yml calls it as a reusable workflow), issuer
    `https://token.actions.githubusercontent.com`, GitHub workflow SHA extension = the run's commit.
  - Each image is built by a job whose name contains the image name (`python`, `java`), with a step
    named exactly `Verify DHI base signature` that verifies the DHI base (`cosign verify --key
    https://dhi.io/keyring/latest.pub --experimental-oci11`, logged in to `dhi.io` with the
    `DHI_USERNAME`/`DHI_TOKEN` secrets) before building.
- How the live tests pick the images: the ref is `GOLDEN_REF` (`refs/heads/<branch>`) when set, else
  the checked-out branch — the PRD branch now, `main` after the merge; nothing is hard-coded to
  `main`. They take the latest successful `golden.yml` run on that branch (`gh api`) whose commit is an
  ancestor of HEAD (or HEAD) and contains the last commit touching `images/golden`, then verify
  `…/golden/<name>:sha-<that commit>` by digest, with the identity regexp bound to this repository's
  workflow file on that ref and `--certificate-github-workflow-sha` = that commit. A foreign
  repository's identity and this repository's `spike.yml` identity must both be rejected. The DHI
  check reads `DHI_USERNAME` and `DHI_TOKEN` from the environment (login through a throwaway
  `DOCKER_CONFIG`, token on stdin) and verifies the provenance's dhi.io digest against
  `https://dhi.io/keyring/latest.pub`; the golden image itself must not verify against that key.
- Harbor (CAT-006): the test starts an execution of `golden-from-ghcr` (admin API
  `POST /replication/executions`), polls it for up to 900 s while its status is in progress
  (`InProgress`, `Running`, `Pending`, `Scheduled` or empty), fails unless it ends `Succeed` (the
  replication API's word; `Success`, the job service's, is accepted too), then expects
  `golden/<name>@<GHCR digest>` in Harbor (repositories flattened to `golden/python`,
  `golden/java`) and the same verification on `harbor.127.0.0.1.nip.io/golden/<name>@<digest>` with
  the CA of Secret `gateway/wildcard-nip-io-tls`.
- Local CA at runtime (Decision 4, `CAT-D04`), assumed by `tests/platform/trust_bundle.bats` and
  `tests/ci/golden_dockerfiles.bats`:
  - Argo CD Application `trust-manager` (namespace `argocd`, Synced, Healthy) installs the
    `trust-manager` chart; `task up` still converges.
  - A cluster-scoped `Bundle` `harborlab-trust` (`bundles.trust.cert-manager.io`; a `ClusterBundle`
    `harborlab-trust` of `clusterbundles.trust-manager.io` is accepted instead if the chart serves only
    that API) sources the public certificate of the local CA — key `tls.crt` of Secret
    `cert-manager/harborlab-ca` (the ExternalSecret-delivered CA, in trust-manager's trust namespace
    `cert-manager`) or a copy of that certificate; its spec never names `tls.key` nor sets
    `includeAllKeys: true`.
  - Target: ConfigMap `harborlab-trust` in every namespace labelled `harborlab.io/tier=workload` and
    in no other namespace, with `data["ca.crt"]` (PEM bundle holding the local CA, no private key) and
    `binaryData["truststore.p12"]` (PKCS#12 trust store holding the local CA, password-less:
    trust-manager's default empty password, readable by `openssl pkcs12 -legacy -passin pass:`). The
    PEM alone lets a client trust `https://harbor.127.0.0.1.nip.io` (`/api/v2.0/ping` → 200), whose
    certificate is issued by that CA (`gateway/wildcard-nip-io-tls` `ca.crt` has its fingerprint).
  - The test creates the namespaces `trust-bundle-test-workload` (labelled) and
    `trust-bundle-test-plain` (unlabelled), waits up to 120 s for the labelled copy, and deletes both
    at the end. Only `tls.crt` is read from `cert-manager/harborlab-ca`; the CA key is never fetched.
  - Golden sources `images/golden/{python,java}/Dockerfile` bake no CA: no `COPY`/`ADD` of a
    certificate file or trust store (`.crt`, `.pem`, `.cer`, `.der`, `.p12`, `.pfx`, `.jks`,
    `ca-certificates`, `cacerts`, `certs/`), no `RUN` installing one (`update-ca-certificates`,
    `update-ca-trust`, `keytool -import…`); their final stage sets a `USER` other than `root`/`0`.
  - Tools: `openssl` (already on the Devbox PATH).

M4 interface assumed by `tests/kyverno/**` (run through `tests/kyverno/run.sh`), `tests/chainsaw/**`,
`tests/ci/policy_ci.bats` and `tests/docs/docs.bats` (CAT-009 to CAT-013):
- Tools: Devbox provides the `kyverno` CLI (≥ 1.19) and `chainsaw` (kyverno/chainsaw, ≥ 0.2.15) on top of
  the M0–M3 tools (`kind`, `kubectl`, `helm`, `crane`, `yq`, `jq`). In a cluster, Kyverno ≥ 1.19 (Helm
  chart `kyverno` ≥ 3.9) runs in namespace `kyverno`, and reports are `policyreports.wgpolicyk8s.io/v1alpha2`
  `PolicyReport`s (chart default: OpenReports disabled).
- Policies: every file under `policies/` outside `policies/params/` holds only `policies.kyverno.io/v1` CEL
  policy types (no `ClusterPolicy`/`Policy`, Decision 6). Kyverno writes a denial or warning as
  `Policy <name> failed: <message>`; tests match the policy name and the message below as substrings,
  so a validation message may carry more text (e.g. the image) but must contain its phrase.
- Workload tier: pods (CREATE, UPDATE) in namespaces labelled `harborlab.io/tier=workload`, every image of
  `containers`, `initContainers` and `ephemeralContainers`. Each policy checks one rule only, so that
  each fixture fails exactly one policy (the `kyverno test` suite asserts the other policies pass):
  | File | Kind | Name | `validationActions` | Rule | Message phrase |
  |---|---|---|---|---|---|
  | `policies/workload/image-signature.yaml` | ImageValidatingPolicy | `workload-image-signature` | `[Deny]` | Every image (glob `*`) carries a keyless signature, then a CycloneDX, an SPDX and a SLSA v1 (`https://slsa.dev/provenance/v1`) attestation, each signed by the build identity, checked in that order; `validationConfigurations.mutateDigest: true` rewrites admitted images to their digest (CAT-011) | `image is not signed by the harborlab build-image workflow`; `image has no CycloneDX SBOM attestation signed by the harborlab build-image workflow` (likewise `image has no SPDX SBOM attestation …`, `image has no SLSA provenance attestation …`) |
  | `policies/workload/golden-base.yaml` | ImageValidatingPolicy | `workload-golden-base` | `[Deny]` | Base digest `H` = `digest.sha256` of the `predicate.buildDefinition.resolvedDependencies` entry whose `uri` starts with `oci://` in the SLSA v1 provenance verified against the build identity; `data["sha256.<H>"]` of ConfigMap `kyverno/golden-images` must be `supported` or `deprecated` | absent: `image base is not a golden image of the catalog`; `eol`: `image base is an end-of-life golden image` |
  | `policies/workload/golden-base-deprecated.yaml` | ImageValidatingPolicy | `workload-golden-base-deprecated` | `[Warn, Audit]`, never `Deny` | Same lookup; fails when the status is `deprecated` (Kyverno CEL policies report `fail`, never `warn`: the actions are what admit the pod with a warning and a report entry) | `image base is a deprecated golden image` |
  | `policies/workload/image-labels.yaml` | ImageValidatingPolicy | `workload-image-labels` | `[Deny]` | Image config labels `org.opencontainers.image.source`, `org.opencontainers.image.revision`, `org.opencontainers.image.title`, `io.harborlab.golden.name`, `io.harborlab.owner` present and non-empty (read with the image data library, e.g. `image.GetMetadata(ref).config.config.Labels`); labels only, no signature condition (the CRD requires `attestors`, which this policy need not call) | `image is missing required labels` |
  | `policies/workload/registry.yaml` | ValidatingPolicy | `workload-registry` | `[Deny]` | Every image string starts with one line of `data.workload` of ConfigMap `kyverno/harborlab-registries` | `image is not served from an allowed workload registry` |
  | `policies/workload/pod-security.yaml` | MutatingPolicy | `workload-pod-security` | — | Namespaces (CREATE, UPDATE) labelled `harborlab.io/tier=workload` get exactly two labels added, `pod-security.kubernetes.io/enforce: restricted` and `pod-security.kubernetes.io/enforce-version: latest` (`kyverno test` compares the whole patched Namespace); native Pod Security Admission then denies with `violates PodSecurity "restricted:latest"` | — |

  Build identity (the reusable workflow that builds golden, app and fixture images): issuer
  `https://token.actions.githubusercontent.com`, subject regexp
  `^https://github\.com/naqa92-portfolio-projects/harborlab/\.github/workflows/build-image\.yml@refs/heads/(main|prd-.+)$`,
  transparency log `https://rekor.sigstore.dev`.
- Platform tier: pods in namespaces labelled `harborlab.io/tier=platform` whose name is none of
  `kube-system`, `cilium`, `argocd`, `kyverno`: the bootstrap namespaces are excluded by name, even when
  labelled platform (the Chainsaw case labels them). Both policies only report:
  | File | Kind | Name | `validationActions` | Rule | Message phrase |
  |---|---|---|---|---|---|
  | `policies/platform/registry-allow-list.yaml` | ValidatingPolicy | `platform-registry-allow-list` | `[Audit]` | The registry host of every image (a reference without host is `docker.io`) is one line of `data.platform` of ConfigMap `kyverno/harborlab-registries` | `image registry is not in the platform allow-list` |
  | `policies/platform/vendor-signatures.yaml` | ImageValidatingPolicy | `platform-vendor-signatures` | `[Audit]` | Images under `reg.kyverno.io/kyverno/*` (and `ghcr.io/kyverno/*`), `quay.io/cilium/*` and `quay.io/argoproj/*` verify against their vendor's keyless GitHub Actions identity (Kyverno keeps its signatures in `ghcr.io/kyverno/signatures`: attestor `cosign.source.repository`); other images are not matched | `image is not signed by its vendor` |
- Production params: `policies/params/golden-images.yaml` (M3, generated) and `policies/params/registries.yaml`
  (hand-written): ConfigMap `kyverno/harborlab-registries`, newline-separated lists; `data.workload` is
  exactly `harbor.127.0.0.1.nip.io/golden/` and `harbor.127.0.0.1.nip.io/apps/`; `data.platform` is
  `harbor.127.0.0.1.nip.io`, `docker.io`, `quay.io`, `ghcr.io`, `registry.k8s.io`, `dhi.io`,
  `reg.kyverno.io` (compared as sets with the E2E list). Deploying policies and params to the live cluster
  is not asserted by M4 tests.
- E2E params (test fixtures in `tests/chainsaw/params/`, copied verbatim into the `kyverno test` contexts):
  the ephemeral cluster has no Harbor, so the policy workflow applies them instead of `policies/params/`,
  while the production policy files are applied unchanged. `golden-images.yaml` holds every production
  `supported` entry unchanged and never a production entry with another value (production `deprecated`/`eol`
  versions of the catalog may be left out: the E2E cases use their own fixture bases), plus fixture-only entries
  that never enter `images/catalog.yaml`:
  `sha256.1bab11a9…6235` `deprecated` and `sha256.9a9fd7ff…2217` `eol`, the DHI `python:3.12-debian13` and
  `python:3.11-debian13` digests standing in for retired golden bases. `registries.yaml` holds the
  production lists plus the workload prefix `ghcr.io/naqa92-portfolio-projects/harborlab/fixtures/`; the
  registry rule is still proven by `offlist/compliant`, a fully compliant image outside that prefix.
  `tests/ci/policy_ci.bats` enforces this superset relation and each fixture base's status.
- Fixture images, sources in `tests/fixtures/images/<case>/Dockerfile` (test files), published by
  `.github/workflows/fixtures.yml` (name `fixtures`, coder-owned: push to `main` and `prd-*` touching
  `tests/fixtures/images/**`, the workflow or `build-image.yml`, plus `workflow_dispatch`; DHI secrets passed
  to `build-image.yml`) as public GHCR packages, each tagged `e2e` (re-pointed at every publish; the suites
  resolve `:e2e` at run time):
  | Reference | Published as |
  |---|---|
  | `ghcr.io/naqa92-portfolio-projects/harborlab/fixtures/compliant:e2e` | `build-image.yml`, context `tests/fixtures/images/compliant` (`FROM` the supported golden python digest, nothing else) |
  | `…/fixtures/missing-labels:e2e` | `build-image.yml` on its context (golden python, required labels blanked: a Dockerfile cannot unset an inherited label) |
  | `…/fixtures/deprecated-base:e2e`, `…/fixtures/eol-base:e2e`, `…/fixtures/unknown-base:e2e` | `build-image.yml` on the same-named context (DHI python 3.12 / 3.11 / 3.13 base, required labels set, `USER 65532:65532`) |
  | `…/fixtures/unsigned:e2e` | copy of the compliant digest with no referrer (no signature, no attestation, no `sha256-*` tag) |
  | `…/fixtures/foreign-signer:e2e` | copy of the compliant digest signed (and attested) keyless by the `fixtures.yml` job itself, identity `…/fixtures.yml@refs/heads/<branch>`, never by `build-image.yml` |
  | `…/fixtures/no-sbom:e2e` | copy of the compliant digest whose referrers hold only the `build-image.yml` signature and SLSA provenance bundles (CycloneDX and SPDX bundles left out) |
  | `ghcr.io/naqa92-portfolio-projects/harborlab/offlist/compliant:e2e` | copy of the compliant digest with all its referrers (signature and the three attestations) |

  Harbor replication of the fixtures is not needed by M4 (the M9 demos decide). Renovate must leave
  `tests/**` alone (`ignorePaths`): the fixture bases are pinned to their E2E status.
- `kyverno test` runner `tests/kyverno/run.sh [<tier>/<policy>…]` (tester-owned harness): the Kyverno CLI verifies
  signatures only on digest references (`verifyDigest`) and reads image metadata only from its context.
  One suite per policy (`tests/kyverno/<tier>/<policy>/kyverno-test.yaml`, the kyverno/policies layout),
  sharing its tier's `resources/`, `values.yaml` and `context.yaml`: the Kyverno CLI 1.19 deadlocks when two
  ImageValidatingPolicies evaluate the same resource (kyverno/sdk#125), so the script refuses a suite that
  loads more than one policy. It copies `tests/kyverno` and `policies` to a temp directory, pins each tag-only
  pod image to the digest its tag serves now (`crane digest`), writes each image's registry manifest and
  config into the suite's context (committed contexts never hold image data; the script refuses one that
  does), then runs `kyverno test <suite> --registry` for every suite found (no argument) and exits non-zero
  if any fails. Each suite is bounded by `KYVERNO_SUITE_TIMEOUT` (default 600 s; a hang fails that suite);
  `crane` and `kyverno test` calls failing with a registry rate-limit error (`TOOMANYREQUESTS`, `429 Too Many
  Requests`) are retried with exponential backoff (`REGISTRY_RATE_LIMIT_ATTEMPTS` default 4,
  `REGISTRY_RATE_LIMIT_BACKOFF` default 15 s); any other failure, and the last attempt's, stands.
- Policy workflow `.github/workflows/policies.yml` (name `policies`): `pull_request` without branch filter,
  with no `paths` filter or one listing `policies/**` (and nothing under `policies` in `paths-ignore`);
  blocking jobs whose `run` steps literally hold (possibly wrapped in `devbox run --`): `tests/kyverno/run.sh`
  in one job; in one job `kind create cluster` (or `uses: helm/kind-action`), `helm upgrade --install …
  kyverno …` (or `helm install`), `kubectl apply` of `tests/chainsaw/params`, `policies/workload` and
  `policies/platform` (not `policies/params`), a wait for the policies to be ready, then
  `chainsaw test --test-dir tests/chainsaw`. Public images only: no registry credential.
- Chainsaw conventions: each case gets its own namespace from `namespaceTemplate` carrying only the tier
  label; pods set `nodeSelector: {harborlab.io/e2e: unschedulable}` (admission is under test, images are
  never pulled); admission goes through `kubectl apply` in a script so stderr carries denials and
  warnings; PolicyReports are matched by `scope` within 150 s; `bootstrap-excluded` labels the existing
  `kube-system` and `kyverno` namespaces `harborlab.io/tier=platform` (label removed at cleanup) and creates
  `cilium` and `argocd`; `digest-mutation` reads the tag's digest with `crane` at test time.
- Docs: `docs/THREAT-MODEL.md` has a heading containing "bootstrap" whose section states the exclusion and
  names `kube-system`, `cilium`, `argocd` and `kyverno`.

M5 interface assumed by `tests/ci/app_contract.bats`, `tests/supply-chain/app_images.bats` (CAT-007),
`tests/supply-chain/harbor_replicated.bats` (CAT-006, apps part) and `tests/platform/golden_path_apps.bats`
(CAT-015); the supply-chain tests share `tests/supply-chain/apps.bash` (loaded after `golden.bash`):
- Tools: nothing beyond the M0–M4 Devbox tools and the host `gh`.
- App sources (Decision 5):
  - `apps/dt-bridge/`: Python 3.13 / FastAPI skeleton managed by uv (`pyproject.toml` + `uv.lock`, ruff
    lint/format configuration there); HTTP on port 8080, `GET /healthz` → 200 with JSON `{"status": "ok"}`.
    Its real logic comes at M6.
  - `apps/hello-java/`: Spring Boot on Java 21; HTTP on port 8080, `GET /` → 200 with a non-empty body.
  - Each has `apps/<app>/Dockerfile`: every `FROM` is a digest-pinned golden reference
    (`ghcr.io/naqa92-portfolio-projects/harborlab/golden/<name>[:<tag>]@sha256:<digest>` or
    `harbor.127.0.0.1.nip.io/golden/<name>[:<tag>]@sha256:<digest>`) whose (`name`, `digest`) is a `supported`
    entry of `images/catalog.yaml`, or an earlier stage alias; the final stage is `FROM` a golden reference
    directly, `python` for dt-bridge and `java` for hello-java (Temurin JRE). No `COPY`/`ADD` of a certificate
    or trust store, no `RUN` installing a CA, no `RUN`/`ENTRYPOINT`/`CMD` calling cosign, syft, trivy, grype or
    notation; a `USER` in the final stage, if any, is not `root`/`0` (the lint's `trivy-config` check wants a
    non-root `USER`). The governance labels come from the golden image. Kubernetes manifests live where the
    coder chooses (e.g. `apps/<app>/deploy/`) and pass `task lint`.
- App workflows `.github/workflows/dt-bridge.yml` and `.github/workflows/hello-java.yml` (file name = app
  name; the live tests list runs of that file): `on.push.branches` lists `main` (and `prd-*` during the PRD,
  so that images exist before the merge), `on.push.paths` lists `apps/<app>/**`. Exactly one job, with no
  keys other than `name`, `uses`, `with`, `permissions`; `uses: ./.github/workflows/build-image.yml` (or
  `naqa92-portfolio-projects/harborlab/.github/workflows/build-image.yml@<40 hex>`), the file's only `uses:`
  line; `with` is exactly `{image: apps/<app>, context: apps/<app>}`; no `secrets` (a golden base needs no
  DHI credential); top-level and job `permissions` absent or granting only `contents: read`,
  `packages: write`, `id-token: write`; no key or value mentions cosign, syft, trivy, grype, notation,
  sigstore, attest, sbom or provenance (comments are not read).
- `build-image.yml` keeps a named step whose `run` calls `trivy` with `--vex oci`, unconditional (no `if`),
  without `continue-on-error: true`, placed before the step running `cosign sign`. The live test finds the
  step by that name in `build-image.yml` at the built commit and requires it concluded `success` in the app
  run's jobs.
- Images: public `ghcr.io/naqa92-portfolio-projects/harborlab/apps/{dt-bridge,hello-java}`, tag
  `sha-<github.sha>`. The live tests take, per app, the latest successful `<app>.yml` run on the branch of
  `GOLDEN_REF` (or the checked-out branch) whose commit is in the checked-out history and contains the last
  commit touching `apps/<app>` or `.github/workflows/<app>.yml`, then verify `…/apps/<app>@<digest of
  sha-<commit>>`: `cosign verify` and `verify-attestation` (`cyclonedx` with `components`, `spdxjson` with
  `packages`, `slsaprovenance1`) with issuer `https://token.actions.githubusercontent.com`, identity
  `^https://github\.com/naqa92-portfolio-projects/harborlab/\.github/workflows/build-image\.yml@<ref>$`
  only, `--certificate-github-workflow-sha` = the commit; the app's own caller identity
  (`…/workflows/<app>.yml@…`), a foreign repository and `spike.yml` must not verify. The SLSA provenance
  records the commit (`digest.gitCommit`) and exactly one `oci://` dependency whose `digest.sha256` is the
  digest of the final `FROM` of `apps/<app>/Dockerfile` at that commit, a `supported` catalog entry.
  `build-image.yml` today records the first `FROM`: a multi-stage app Dockerfile needs it to record the
  final stage's base instead (a builder stage is not the image's base).
- Harbor (CAT-006, apps part): the test resolves both app builds, runs `apps-from-ghcr` through the admin API
  exactly as `golden-from-ghcr` (poll ≤ 900 s, `Succeed`/`Success`), then expects `apps/<app>@<GHCR digest>`
  in Harbor (flattened to `apps/dt-bridge`, `apps/hello-java`) and the same verification on
  `harbor.127.0.0.1.nip.io/apps/<app>@<digest>` with `--registry-cacert` (CA of `gateway/wildcard-nip-io-tls`).
- Deployment (CAT-015): Argo CD Applications `dt-bridge` and `hello-java` (namespace `argocd`, children of
  `root`; `task up` still converges), Synced and Healthy, each listing in `status.resources` the Deployment
  `<app>` of namespace `<app>` (`dt-bridge` matches the Harbor webhook address of M2). Namespaces `dt-bridge`
  and `hello-java` are labelled `harborlab.io/tier=workload` and carry
  `pod-security.kubernetes.io/enforce=restricted` (added by `workload-pod-security`). Each Deployment is fully
  available (`availableReplicas` = `updatedReplicas` = `replicas` ≥ 1) and its pods (its `matchLabels`
  selector) are Running and Ready. Service `<app>` in namespace `<app>` exposes port 8080; the test calls it
  through the API server service proxy (`/api/v1/namespaces/<app>/services/http:<app>:8080/proxy/…`).
- Pod images: every container and init container image is `harbor.127.0.0.1.nip.io/{apps,golden}/…@sha256:<64
  hex>`; the container named `<app>` runs `harbor.127.0.0.1.nip.io/apps/<app>[:<tag>]@sha256:<digest>`, one
  digest across the pods, which verifies against the admission identity regexp
  `…/build-image\.yml@refs/heads/(main|prd-.+)$` (Harbor CA from `gateway/wildcard-nip-io-tls`) with a SLSA
  provenance naming exactly one base, a `supported` catalog entry.
- Live admission: the live Kyverno must reach `https://harbor.127.0.0.1.nip.io` from inside the cluster and
  trust the local CA (today a workload pod on a Harbor reference fails with `Get
  "https://harbor.127.0.0.1.nip.io/v2/": dial tcp 127.0.0.1:443: connect: connection refused`: the name
  resolves to the pod's loopback). Admission is proven at test time, not from PolicyReports: a pod recreated
  by its ReplicaSet gets only Audit results at admission, and the `pass` results of the Deny policies wait for
  Kyverno's hourly background scan, so PolicyReport `pass` results are eventual and not asserted in the test
  window. At test time, a server-side dry-run of pod `admission-probe` carrying the labels and exact spec of
  the first running app pod (same image, same digest) in the app namespace is admitted without `Warning`, and
  the same spec with the app container on `ghcr.io/naqa92-portfolio-projects/harborlab/apps/<app>@<digest>`
  is denied naming `workload-registry` (control: the policies enforce there). Each workload policy is served
  by a validating webhook of the `kyverno` service whose `clientConfig.service.path` has the policy name as a
  segment (Kyverno 1.19: `/ivpol/validate/<policy>`, `/vpol/<policy>[/<policy>…]`), `sideEffects` `None` or
  `NoneOnDryRun` (dry-runs reach it), rules covering pod `CREATE`, a `namespaceSelector` and `objectSelector`
  matching the app namespace's and pod's labels, and no `matchConditions`. The Deny policies
  (`workload-image-signature`, `workload-golden-base`, `workload-image-labels`, `workload-registry`, whose
  `validationActions` hold `Deny`) have only `failurePolicy: Fail` webhooks there; `workload-golden-base-deprecated`
  (`[Warn, Audit]`, CAT-010) keeps its `Ignore` webhook and its pass is shown by the absence of `Warning`.
- Local CA at runtime (Decision 4): the container `<app>` mounts a volume whose `configMap.name` is
  `harborlab-trust` at `/etc/harborlab-trust` (whole ConfigMap, no `subPath`), so it reads
  `/etc/harborlab-trust/ca.crt` and `/etc/harborlab-trust/truststore.p12`.
  - dt-bridge: env `SSL_CERT_FILE=/etc/harborlab-trust/ca.crt`; `python` is on the container PATH and
    `ssl.create_default_context().get_ca_certs(binary_form=True)`, run through `kubectl exec -c dt-bridge`,
    includes the local CA (SHA-256 of `cert-manager/harborlab-ca` `tls.crt`).
  - hello-java: env `JAVA_TOOL_OPTIONS` carrying `-Djavax.net.ssl.trustStore=/etc/harborlab-trust/truststore.p12`
    and `-Djavax.net.ssl.trustStoreType=PKCS12` (password-less store); `java` is on the container PATH and
    `java -XshowSettings:properties -version`, run through `kubectl exec -c hello-java`, prints
    `javax.net.ssl.trustStore = /etc/harborlab-trust/truststore.p12` and `javax.net.ssl.trustStoreType = PKCS12`.

M6 interface assumed by `tests/platform/dt_sbom_upload.bats` (CAT-016), `tests/platform/dt_vex.bats` (CAT-017),
both loading `tests/supply-chain/{golden,apps}.bash` then `tests/platform/dt.bash`, by the M6 lines of
`PLATFORM_CREDENTIALS` in `tests/platform/secrets.bats` (CAT-024), and by `apps/dt-bridge/tests/*` and
`tests/ci/python_lint.bats` (CAT-019):
- Tools: nothing new on the Devbox PATH for the live tests (`crane auth token`, `cosign`, `curl`, `jq`). `uv` must be
  on the PATH of `devbox run` (the host's today; adding `uv` to `devbox.json` makes it reproducible).
- Dependency-Track 5.1 (Decision 14): Argo CD Application `dependency-track` (namespace `argocd`, child of `root`,
  Synced and Healthy; `task up` still converges), chart `dependency-track` of `https://dependencytrack.github.io/helm-charts`
  (≥ 2.5.0, appVersion 5.1.x), release and namespace `dependency-track` (a platform namespace: no
  `harborlab.io/tier=workload` label), `apiServer.topology: monolith`, frontend enabled. Database (Decision 12): CNPG
  Cluster `dependency-track/dependency-track-db`, `instances: 1`, `bootstrap.initdb.secret.name:
  dependency-track-db-credentials`; the chart reads it through `database.existingSecret` and a `jdbcUrl` on
  `dependency-track-db-rw`. No credential, KEK or API key in Git or in Helm values: every one comes from an
  ExternalSecret (a `secretManagement` KEK, if used, likewise).
- Endpoint: `https://dependency-track.127.0.0.1.nip.io` through the Cilium Gateway (chart `httpRoute`, which routes
  `/api` to the API server and `/` to the frontend), certificate issued by the local CA (tests trust
  `gateway/wildcard-nip-io-tls` `ca.crt`). Tests use the v1 REST API only: `GET /api/v1/project/lookup?name=&version=`
  (404 when absent), `GET /api/v1/project/{uuid}` (`lastBomImport`, epoch ms), `GET /api/v1/project?name=`,
  `GET /api/v1/component/project/{uuid}` (`pageSize`/`pageNumber`, `X-Total-Count`),
  `GET /api/v1/finding/project/{uuid}?suppressed=true` (`vulnerability.{uuid,vulnId,aliases}`, `component.{uuid,purl}`),
  `GET /api/v1/analysis?project=&component=&vulnerability=` (`analysisState`, `analysisJustification`,
  `analysisDetails`), header `X-Api-Key`.
- API key: one DT team for dt-bridge whose key has `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`,
  `VIEW_VULNERABILITY`, `VULNERABILITY_ANALYSIS` (least privilege: no `PORTFOLIO_MANAGEMENT`, no admin). The tests read
  that key from Secret `dt-bridge/dependency-track-api-key` key `api-key` and send it on stdin.
- Credentials (OpenBao KV v2 → ExternalSecret through `ClusterSecretStore/openbao`, seeded once and never overwritten):
  | OpenBao path | Fields | Kubernetes Secret (keys) |
  |---|---|---|
  | `secret/platform/dependency-track-db` | `username`, `password` | `dependency-track/dependency-track-db-credentials` (`username`, `password`, type `kubernetes.io/basic-auth`) |
  | `secret/platform/dependency-track-admin` | `password` (the DT `admin` password, set at bootstrap; the default `admin`/`admin` never survives it) | none required (`-\|-`) |
  | `secret/platform/dependency-track-api-key` | `api-key` (the dt-bridge team key, created by the bootstrap and written back to OpenBao) | `dt-bridge/dependency-track-api-key` (`api-key`) |
  | `secret/platform/harbor-robot-dt-bridge` (M2) | `username`, `password` | `dt-bridge/harbor-robot-dt-bridge` (`username`, `password`) |
  | `secret/platform/dhi` (M2) | `username`, `token` | `dt-bridge/dhi-credentials` (`username`, `token`), besides `registry-mirror-test/dhi-pull` |
- Webhook: dt-bridge serves `POST /harbor/events` on port 8080 (Service `dt-bridge/dt-bridge`), the address of the M2
  Harbor webhook policy `dt-bridge` (`PUSH_ARTIFACT`, `REPLICATION`) on `golden` and `apps`. The event is only a
  trigger: dt-bridge never takes SBOM or VEX content from the request body, it reads everything from Harbor with
  `robot$dt-bridge`. `sha256-*` tags (referrers fallback indexes) and signature/attestation manifests are not images:
  they never become DT projects. A `REPLICATION` event of an execution that found the artifact already in Harbor
  must still lead to an upload (the test triggers a replication of an image replicated before and requires a BOM
  import after it; if Harbor sends no event in that case, report it rather than weaken the test).
- DT project naming: name = Harbor `<project>/<repository>` (`apps/hello-java`, `golden/python`), version = tag
  (`sha-<40 hex>`); created on upload (`autoCreate`). Within 300 s of the end of the replication, the project's
  `lastBomImport` is not older than the replication start and its component purls equal the purls of the verified
  CycloneDX attestation (compared after dropping subpaths, decoding `%2B %3A %40 %7E` and sorting qualifiers; nested
  components included; components without purl ignored).
- SBOM source: the CycloneDX attestation signed at build time (ADR 0001): Harbor's referrers API on the image digest
  (`GET /v2/<project>/<repository>/referrers/<digest>`), the manifest whose annotation
  `dev.sigstore.bundle.predicateType` is `https://cyclonedx.org/bom`; its single layer is a Sigstore bundle v0.3
  (`application/vnd.dev.sigstore.bundle.v0.3+json`) whose `dsseEnvelope.payload` is the in-toto statement. The
  predicate is uploaded unchanged (the golden SBOMs are CycloneDX 1.7 with ~3000 components). No SBOM generator
  (syft, trivy, cdxgen) runs in dt-bridge.
- DHI OpenVEX (criterion 17): for a golden image, the DHI base is the single `oci://dhi.io/…` dependency of its
  verified SLSA provenance. dhi.io serves each platform manifest's attestations as OCI referrers
  (`GET https://dhi.io/v2/<repo>/referrers/<platform digest>?artifactType=application/vnd.in-toto+json`, bearer
  token for the `dhi` credentials): the manifest annotated `in-toto.io/predicate-type: https://openvex.dev/ns/v0.2.0`
  has one layer, a plain in-toto statement (not DSSE; its cosign signature is a referrer of that manifest, key
  `https://dhi.io/keyring/latest.pub`) whose predicate is the OpenVEX document. Pick the platform of the golden image
  and, among several documents, the latest `last_updated`. DHI statements name Debian **source** packages
  (`pkg:deb/debian/openssl@…?os_distro=trixie&os_name=debian&os_version=13`), repeat products, and include
  `under_investigation` statements; the attested syft SBOM lists binary packages with `upstream=<source>`
  (`pkg:deb/debian/libssl3t64@…?arch=amd64&distro=debian-13.7&upstream=openssl`). A product covers an SBOM component
  of the same type and namespace whose name or `upstream` qualifier (version part dropped) is the product name, at
  the product version when it has one (percent-decoded). DT applies VEX only to existing findings and resolves a VEX
  vulnerability by id (and source): the VEX is uploaded after the BOM's processing (its token `COMPLETED` or
  `FAILED`), **also when DT lists no finding for its statements** (DT 5.1 matches OSV Debian advisories, which name
  source packages, by exact purl name and ignores `upstream=`: DependencyTrack/dependency-track#6132, #6957), and a
  CVE that DT holds under another id (OSV `DEBIAN-CVE-…`, GHSA) with the CVE as alias may be emitted under DT's id
  (the test resolves ids through the finding aliases and `vulnerabilities[].references[].id`).
- VEX observables (criterion 17): after each VEX upload DT answers HTTP 200, dt-bridge logs to stdout one JSON line
  (the existing `JsonFormatter`, one object per line) `{"message": "DHI VEX uploaded", "image": "golden/python",
  "tag": "sha-<40 hex>", "token": "<token of the PUT /api/v1/vex answer>", "project_uuid": "<projectUuid of that
  answer>", "vex": {<the CycloneDX VEX document uploaded, as a JSON object>}}`; its `SBOM uploaded` line carries the
  BOM upload `token` too. The live test reads the logs of the pods `app.kubernetes.io/name=dt-bridge` (container
  `dt-bridge`) since the replication start, takes the last `DHI VEX uploaded` entry of `golden/python` `sha-<commit>`
  and requires: a token distinct from the BOM token; `project_uuid` = the DT project of that name and version; the
  VEX is the conversion of the DHI OpenVEX on the attested SBOM (`bomFormat` CycloneDX, `specVersion` 1.4–1.7; every
  component has the `bom-ref` and `purl` of an attested SBOM component and its purl is a component of the DT
  project; every vulnerability affects only VEX components, matches a DHI `not_affected` statement whose products
  cover all of them, has `analysis.state` `not_affected`, the mapped `analysis.justification` (absent when none) and
  an `analysis.detail` containing the document author, the OpenVEX justification label, `status_notes` and
  `impact_statement` (those present); every `not_affected` statement covering attested components, unless another
  statement gives its CVE another status, is converted for each component it covers; at least one statement covers
  an attested component, non-vacuous); then, within 600 s of the replication, `GET /api/v1/event/token/{token}`
  answers `status: COMPLETED` (DT 5.1 answers no `status` for a token it does not know, `FAILED` fails at once).
  Guard that becomes the full criterion once DT matches Debian source packages: each DT finding covered by a DHI
  `not_affected` statement (its `vulnId` or one of its aliases equals the statement's name or aliases, and a product
  covers its component) must reach `NOT_AFFECTED` with `analysisJustification` mapped as below and
  `analysisDetails` containing the same vendor texts. Applying DHI VEX to app images built on a golden base is
  allowed, not asserted.
- Justification mapping (OpenVEX → CycloneDX → DT): `component_not_present` and `vulnerable_code_not_present` →
  `code_not_present` → `CODE_NOT_PRESENT`; `vulnerable_code_not_in_execute_path` → `code_not_reachable` →
  `CODE_NOT_REACHABLE`; `inline_mitigations_already_exist` → `protected_by_mitigating_control` →
  `PROTECTED_BY_MITIGATING_CONTROL`; `vulnerable_code_cannot_be_controlled_by_adversary` has no CycloneDX equivalent
  (CycloneDX/specification#609): no `justification` (DT `NOT_SET`), the label only in the detail. Statuses:
  `not_affected` → `not_affected`; the other OpenVEX statuses (`affected`, `fixed`, `under_investigation`) are known,
  their mapping is not asserted; anything else is an error.
- dt-bridge modules imported by pytest (`apps/dt-bridge/src/dt_bridge/`), sync API:
  - `dt_bridge.sbom`: `extract_cyclonedx_sbom(bundle: bytes) -> dict` returns the in-toto predicate of a Sigstore
    bundle whose `predicateType` is `https://cyclonedx.org/bom` (or `https://cyclonedx.org/bom/v1.x`), unchanged;
    raises `AttestationError` for another predicate type (message naming it), invalid JSON, no `dsseEnvelope`, a
    payload that is not base64, or a `payloadType` other than `application/vnd.in-toto+json`.
  - `dt_bridge.vex` (Decision 14, the only module reading OpenVEX statement vocabulary — `impact_statement`,
    `status_notes`, the justification labels — so it can be deleted when DT imports OpenVEX):
    `openvex_to_cyclonedx(document: dict, sbom: dict) -> dict` returns a CycloneDX VEX (`bomFormat: CycloneDX`,
    `specVersion` 1.4–1.7) whose `components` are the covered SBOM components (their own `bom-ref` and `purl`, each
    once) and whose `vulnerabilities[]` carry `id` (the OpenVEX name), `analysis.state`, `analysis.justification`
    (mapping above, absent when none), `analysis.detail` (author, label, notes, impact statement) and `affects[].ref`
    to those bom-refs; statements covering no SBOM component are left out. Raises `VexConversionError` for an
    unknown status (message naming it), a non-object document, an `@context` outside `https://openvex.dev/ns`,
    missing or non-list `statements`, a statement without `vulnerability.name`, without products, with a product
    `@id` that is not a purl, with an unknown justification, or `not_affected` without justification nor
    `impact_statement`.
  - `dt_bridge.dt_client`: `DependencyTrackClient(base_url, api_key, *, transport=None)` (httpx; `transport` is
    the test's `httpx.MockTransport`); `upload_bom(project_name, project_version, bom: dict) -> str` sends
    `PUT <base_url>/api/v1/bom` with `X-Api-Key` and JSON `{projectName, projectVersion, autoCreate: true, bom:
    base64(JSON)}` and returns the response `token`; `upload_vex(project_name, project_version, vex: dict)` sends
    `PUT /api/v1/vex` with `{projectName, projectVersion, vex: base64(JSON)}`. Errors, all subclasses of
    `DependencyTrackError`, never carrying the API key in their message: `DependencyTrackUnauthorized` (401),
    `DependencyTrackServerError` (5xx, attribute `status_code`), `DependencyTrackTimeout` (httpx timeout).
  - `apps/dt-bridge/pyproject.toml`: `pytest` in the `dev` group, `httpx` a runtime dependency, `[tool.pytest.ini_options]
    pythonpath = ["src"]` (so `cd apps/dt-bridge && uv run pytest` imports `dt_bridge`), and
    `[tool.ruff.lint.per-file-ignores] "tests/**" = ["S101"]` (pytest asserts); `uv.lock` updated. The tests import
    `dt_bridge.*` as first-party (a separate isort block), which ruff only recognises once the modules exist.
- CI: a workflow other than `.github/workflows/dt-bridge.yml` (whose single-`uses` shape CAT-007 fixes) triggers on
  `pull_request` with no branch filter and `paths` absent or listing `apps/dt-bridge/**` (or `apps/**`), and in a
  job without `continue-on-error: true` runs, from blocking steps whose `working-directory` (step, job or workflow
  default) is `apps/dt-bridge` or whose `run` names it, `pytest`, `ruff check` and `ruff format --check`.
- Memory (criterion 22, asserted at M8): the whole cluster must stay ≤ 12 GiB (`kubectl top nodes`, working set
  including active page cache; 10 GiB when this was written). DT 5.1 is the heaviest component:
  budget ≈ 1.5–2 GiB for the API server (JVM heap capped through `JAVA_OPTIONS`/`-XX:MaxRAMPercentage`, container
  limit set), ≤ 128 Mi for the frontend, ≤ 512 Mi for the CNPG instance; mirror only the vulnerability sources the
  golden images need (OSV for Debian, PyPI, Maven, GitHub advisories), not a full NVD mirror, unless measured to fit.

M7 interface assumed by `tests/platform/runtime_vex.bats` (CAT-018, loading `tests/supply-chain/{golden,apps}.bash`
then `tests/platform/dt.bash`) and the Kubescape tests of `apps/dt-bridge/tests/test_vex.py` (CAT-018). Kubescape
data model taken from upstream (`kubescape/kubevuln` `docs/VEX.md`, `repositories/apiserver.go`;
`kubescape/k8s-interface` `instanceidhandler/v1`; chart `kubescape-operator` `values.yaml`):
- Tools: nothing new on the Devbox PATH (`kubectl`, `jq`, `curl`, `cosign`).
- Kubescape operator (Decision 13): Argo CD Application `kubescape` (namespace `argocd`, child of `root`, Synced and
  Healthy; `task up` still converges), chart `kubescape-operator` of `https://kubescape.github.io/helm-charts/` at an
  exact version (1.40.4, the latest release when this was written), release and namespace `kubescape`, `clusterName:
  harborlab`. `kubescape` is a platform namespace (no `harborlab.io/tier=workload` label; the node agent is
  privileged, so no Pod Security `restricted` label either). Sync wave ≤ 3, before the workloads (wave 4), so on a
  fresh `task up` the node agent sees the workload containers from their start. No ARMO cloud backend: no account,
  access key or `server`; nothing leaves the cluster but Grype database downloads. Images come from `quay.io/kubescape`
  through the Harbor quay.io proxy cache (platform tier: allow-list reported, not denied).
- Capabilities enabled: `vulnerabilityScan` (kubevuln: syft SBOM + Grype), `relevancy`, `vexGeneration`,
  `configurationScan` (NSA and CIS frameworks), `nodeScan` (CIS node checks), `runtimeObservability`,
  `runtimeDetection` (criterion 20, asserted at M8). Disabled to fit the memory budget: `continuousScan`,
  `networkPolicyService`, `networkEventsStreaming`, `nodeProfileService`, `admissionController` (Kyverno is the only
  admission), `httpDetection`, `seccompProfileService`, `malwareDetection`, `autoUpgrading`, `syncSBOM`,
  `manageWorkloads`, `prometheusExporter` (M8 may enable it). Only the VEX behaviour is asserted at M7.
- Observed workloads: every namespace except the chart's default `excludeNamespaces` (`kubescape`, `kube-system`, …);
  at least the workload namespaces `dt-bridge` and `hello-java` must be observed (`includeNamespaces` empty or
  listing them).
- Where Kubescape publishes its OpenVEX: `OpenVulnerabilityExchangeContainer` objects, API
  `spdx.softwarecomposition.kubescape.io/v1beta1`, resource `openvulnerabilityexchangecontainers`, namespace
  `kubescape`, served by the Kubescape storage aggregated APIService `v1beta1.spdx.softwarecomposition.kubescape.io`
  (`Available=True`; not a CRD). A list returns metadata only (`spec.statements: null`) unless the request carries
  `resourceVersion=fullSpec` (kubescape/storage `pkg/registry/file/storage.go`, `GetList`); a single `get` returns
  the full spec. The test and dt-bridge list with `kubectl get --raw
  "/apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/kubescape/openvulnerabilityexchangecontainers?resourceVersion=fullSpec"`
  (or its API equivalent), which the `list` verb covers. The relevancy document of a container instance (kubevuln `ScanCP` flow) is named
  after the instance-ID slug and carries the annotations `kubescape.io/instance-id`
  (`apiVersion-apps/v1/namespace-<ns>/kind-ReplicaSet/name-<replicaset>/containerName-<container>`),
  `kubescape.io/image-id` (the container's image ID, e.g. `harbor.127.0.0.1.nip.io/apps/hello-java@sha256:…`),
  `kubescape.io/image-tag` and `kubescape.io/wlid`. Image-level documents (`ScanCVE`/`ScanRegistry`, named after the
  image slug, no relevancy) state every match `affected`; dt-bridge may skip them, the test reads the instance one.
  `.spec` is the OpenVEX document itself: `@context` `https://openvex.dev/ns/v0.2.0`, `author: kubescape.io`,
  `version` (incremented on every real change), `last_updated`, `statements[]`, one per (vulnerability, package):
  `vulnerability.name` (Grype's id, CVE or GHSA), `vulnerability.aliases`, `products: [{"@id":
  "pkg:oci/<name>@<digest>?repository_url=<registry>/<path, percent-encoded or not>", "subcomponents": [{"@id":
  "<package purl from Kubescape's own syft SBOM: Debian binary packages with upstream=, pypi, maven…>"}]}]`; status
  `not_affected` + `vulnerable_code_not_present` + impact statement `Vulnerable component is not loaded into the
  memory` when no file of the package was loaded, `affected` + `action_statement` when it was (SecurityException
  variants exist, none are used here).
- Observation time: a document exists only for a container seen from its start; the node agent's `learningPeriod`
  (chart default 2m) must end, then kubevuln scans (the first scan downloads the Grype database), later updates
  every `updatePeriod` (10m). The test restarts `hello-java/hello-java` (`kubectl rollout restart`: a new ReplicaSet,
  hence a new instance ID) and waits up to 1200 s from the end of the rollout for the document, dt-bridge's upload and
  the DT token `COMPLETED`.
- Collection by dt-bridge: it lists (polling at most every 60 s) or watches the documents of namespace `kubescape`
  with its own ServiceAccount `dt-bridge/dt-bridge` (a projected token mounted in the dt-bridge container only; the
  pod keeps `automountServiceAccountToken: false` otherwise). RBAC least privilege: one Role in `kubescape` granting
  `get`, `list`, `watch` on `openvulnerabilityexchangecontainers` of `spdx.softwarecomposition.kubescape.io` only,
  bound to that ServiceAccount; no ClusterRole binding, no write verb, no Secret, ConfigMap or other Kubescape
  resource (`vulnerabilitymanifests`, `sbomsyfts`, `applicationprofiles`), nothing in another namespace, and still no
  Secret list or Pod creation in `dt-bridge`. Asserted with `kubectl auth can-i --as
  system:serviceaccount:dt-bridge:dt-bridge`.
- Image reference normalisation (Risk: `docker.io` vs `index.docker.io`), module `dt_bridge.kubescape`:
  `image_reference(value: str) -> ImageReference`, a frozen dataclass with `registry: str`, `repository: str`,
  `tag: str | None`, `digest: str | None`. Accepts an image reference (`[docker://]<registry>/<path>[:<tag>][@sha256:…]`
  or a Docker Hub short name) or a Kubescape product purl `pkg:oci/<name>[@<digest>]?repository_url=<registry>/<path>`
  (digest and repository_url percent-encoded or not). `docker.io`, `index.docker.io`, `registry-1.docker.io` and no
  registry all give `docker.io`, a single-segment Docker Hub repository `library/<name>`; the first path segment is a
  registry when it holds a `.` or a `:` or is `localhost`. `ValueError` for an empty value or a purl whose type is not
  `oci`. A reference whose registry is the Harbor host (of `HARBOR_URL`) and whose first repository segment is a
  governed project (`GOVERNED_PROJECTS`) maps to the DT project name `repository` (`apps/hello-java`) and the version
  of the image tag Harbor holds for its digest (`sha-<40 hex>`; `sha256-*` referrers tags are not versions; the digest
  of a running pod is all Kubescape knows, Kyverno having rewritten the image to its digest). Other references
  (platform images from Docker Hub, quay.io, …) have no DT project and are skipped.
- Conversion (Decision 14, "the same way as criterion 17"): the Kubescape document goes through the same
  `dt_bridge.vex.openvex_to_cyclonedx(document, sbom)` as the DHI one, `sbom` being the attested CycloneDX SBOM of that
  digest in Harbor (read as at M6; Kubescape's own SBOM is never uploaded). OpenVEX vocabulary stays in
  `dt_bridge.vex` only (`test_openvex_conversion_is_isolated_in_vex_module` covers `dt_bridge.kubescape` too).
  Conflicts: a statement of the same vulnerability with another status that names a component's own package (same
  type, namespace, name, version) wins, so that component is not emitted `not_affected` for it; otherwise the
  name-or-`upstream` coverage would let Kubescape's `not_affected` on the `openssl` binary package cover `libssl3t64`
  (`upstream=openssl`), which Kubescape reports `affected` (unit:
  `test_kubescape_affected_package_is_not_marked_not_affected`, fixture `kubescape-openvex.json`).
- Upload: once the DT project version holds the attested SBOM (M6; uploaded first if missing, its token awaited),
  dt-bridge re-keys on DT ids like M6 and sends `PUT /api/v1/vex`, also when DT lists no finding. A document is
  forwarded again whenever its `spec.version` changes, not otherwise.
- Log (the M6 `JsonFormatter`; `LOG_FIELDS` gains `kubescape` and `kubescape_version`): after each upload DT answers
  HTTP 200 and dt-bridge logs `{"message": "Kubescape VEX uploaded", "image": "apps/hello-java", "tag": "sha-<40 hex>",
  "digest": "sha256:<running digest>", "token": "<token of the PUT /api/v1/vex answer>", "project_uuid":
  "<projectUuid of that answer>", "kubescape": "kubescape/<document name>", "kubescape_version": <spec.version>,
  "vex": {<the CycloneDX VEX uploaded>}}`.
- Live assertions: the last entry for the instance document at its current `spec.version`, logged since the restart,
  has a token, the running digest and the DT project `apps/hello-java` version `<tag>`; the VEX is CycloneDX 1.4–1.7,
  its components carry the `bom-ref` and `purl` of attested SBOM components that are DT project components; each
  (vulnerability, component) pair matches a Kubescape `not_affected` statement of that vulnerability (id, alias, or DT
  alias) covering the component, with `analysis.state` `not_affected`, the M6 justification mapping
  (`vulnerable_code_not_present` → `code_not_present`) and a detail holding `kubescape.io`, the label and the impact
  statement; no pair is one Kubescape reports `affected` (or another status) on that very package; every
  `not_affected` statement covering attested components is converted for each of them unless another status of the
  same vulnerability covers it; at least one such pair exists (non-vacuous); the DT token reaches `COMPLETED`. Guard:
  each DT finding covered by an uncontested runtime `not_affected` statement shows `NOT_AFFECTED`, `CODE_NOT_PRESENT`
  and the same texts in `analysisDetails`.
- Grype (Kubescape) and Trivy (CI, Harbor) ids diverge: DT's own ids, aliases and the re-keying of M6 reconcile them;
  the divergence itself is documented in an ADR (M9), not asserted.
- Memory (criterion 22, measured at M8): the kind node used 6.3 GiB (`docker stats`) before M7, and M8 still adds
  VictoriaMetrics, VictoriaLogs and Grafana; Kubescape must stay around 3 GiB in total. The chart defaults do not fit
  (kubevuln requests 1000Mi, limit 5000Mi; node agent up to 1400Mi, at least 600Mi with `nodeSbomGeneration`;
  storage up to 1500Mi): cap kubevuln near 1.5 GiB, the node agent near 700Mi, storage near 512Mi–1Gi, the other
  components at 256Mi or less, and disable the unused capabilities above.

M8 interface assumed by `tests/platform/runtime_alert.bats` (CAT-020), `tests/platform/observability.bats` (CAT-021,
loading `tests/supply-chain/golden.bash`, `tests/platform/dt.bash` and `tests/platform/grafana.bash`),
`tests/platform/memory_budget.bats` (CAT-022) and the M8 lines of `PLATFORM_CREDENTIALS` in `tests/platform/secrets.bats`
(CAT-024). Chart names and APIs checked upstream when this was written (VictoriaMetrics `helm-charts`, VictoriaLogs
`vlagent` docs, `grafana-community/helm-charts`, `kyverno/policy-reporter` 3.10 and `policy-reporter-ui` 2.7,
`kubescape-operator` 1.40.4 and `kubescape/node-agent` v0.3.219 sources):
- Tools: nothing new on the Devbox PATH (`kubectl`, `curl`, `jq`, `yq`, `cosign`, `crane`, `task`); `docker` from the host
  for the `docker stats` diagnostic of CAT-022 only.
- Argo CD Applications (namespace `argocd`, children of `root`, automated sync, Synced and Healthy; `task up` still
  converges): `metrics-server` (chart `metrics-server` of `https://kubernetes-sigs.github.io/metrics-server/`, namespace
  `kube-system`; kind's kubelet certificates need `--kubelet-insecure-tls` or equivalent; APIService
  `v1beta1.metrics.k8s.io` Available), `victoria-metrics` (chart `victoria-metrics-single` of
  `https://victoriametrics.github.io/helm-charts/`), `victoria-logs` (chart `victoria-logs-single`), a log collector
  (chart `victoria-logs-collector`, the `vlagent` DaemonSet, in its own Application or in `victoria-logs`), `grafana`
  (chart `grafana` of `https://grafana-community.github.io/helm-charts`; `grafana/helm-charts` moved there in 2026) and
  `policy-reporter` (chart `policy-reporter` of `https://kyverno.github.io/policy-reporter`, 3.x, with `ui.enabled`).
  VictoriaMetrics, VictoriaLogs, the collector and Grafana live in namespace `observability`, a platform namespace (no
  `harborlab.io/tier=workload`); Policy Reporter in `observability` or its own namespace. Exact chart versions, images
  through the Harbor proxy caches, memory limits set on every container (see Memory).
- Grafana: `https://grafana.127.0.0.1.nip.io` through the Cilium Gateway `platform` (HTTPRoute, certificate of the local
  CA: tests trust `gateway/wildcard-nip-io-tls` `ca.crt`). Admin credentials from OpenBao KV v2 `secret/platform/grafana-admin`
  (fields `username`, `password`, seeded once by `task up` and never overwritten) through an ExternalSecret on
  `ClusterSecretStore/openbao` to Secret `observability/grafana-admin` (keys `admin-user`, `admin-password`; chart
  `admin.existingSecret`); the tests read them into variables and send them as a Basic header on stdin, never printed.
  Plugin `victoriametrics-logs-datasource` installed (chart `plugins`). Provisioned datasources with fixed uids:
  `victoriametrics` (type `prometheus` or `victoriametrics-metrics-datasource`, URL of the in-cluster VictoriaMetrics)
  and `victorialogs` (type `victoriametrics-logs-datasource`, URL of the in-cluster VictoriaLogs). The tests read
  `GET /api/datasources/uid/<uid>`, `GET /api/dashboards/uid/image-posture` and run queries with `POST /api/ds/query`
  (`{queries: [<target> + {refId, datasource: {uid, type}}], from, to}` in epoch ms).
- Dashboard (provisioned from Git, e.g. a sidecar ConfigMap): uid `image-posture`, title containing "image posture".
  Variable `golden`: type query on datasource uid `victoriametrics`, definition `label_values(<selector>, golden)`; the
  test runs `group by (golden) (<selector>)` and requires every distinct `images/catalog.yaml` name among the values.
  "Per golden image" (criterion 21) means per catalog name, the value of the image label `io.harborlab.golden.name`,
  which carries no version: the variable lists each name once whatever its versions, and a panel filtered on
  `$golden` aggregates every version of that name; versions are told apart by the `digest` label of the CVE feed. Four panels,
  each found by a case-insensitive title match that no other panel shares (panels inside rows count): `cve` (e.g. "CVEs
  by severity — before / after VEX"), `signed` ("Signed and attested running images"), `admission` ("Admission
  violations"), `runtime` ("Runtime alerts"). Every target names its datasource uid (`victoriametrics` or `victorialogs`,
  on the target or the panel; no datasource variable) and at least one references `$golden`/`${golden}`; the only other
  variables a target may use are Grafana's `$__range`, `$__range_s`, `$__range_ms`, `$__interval`, `$__interval_ms` and
  `$__rate_interval` (the test substitutes 1h, 3600, 3600000, 1m, 60000, 2m and `golden` textually, then queries the
  last hour). The `cve` and `signed` panels query `victoriametrics`. A panel's value is the sum of the last value of
  each numeric series it returns, or its row count when it returns log lines only.
- Golden attribution: an image belongs to the golden image named by its image config label `io.harborlab.golden.name`
  (inherited from the golden base, required by `workload-image-labels`); the tests read it from Harbor
  (`GET /api/v2.0/projects/<p>/repositories/<r>/artifacts/<digest>` → `extra_attrs.config.Labels`).
- CVE panel feed, metric `harborlab_image_vulnerabilities{golden, image, digest, source, vex, severity}` (gauge, scraped
  by VictoriaMetrics from its exporter, e.g. dt-bridge `GET /metrics` on port 8080): `image` = Harbor
  `<project>/<repository>`, `digest` = `sha256:…`, `severity` ∈ `critical|high|medium|low|unknown` (any other source
  severity → `unknown`), `vex` ∈ `before|after`, and one series per (source, vex, severity), zeros included, for at
  least every catalog entry — each (name, version) at its catalog digest (`golden/<name>@<catalog digest>`), whatever
  its status, `deprecated` and `eol` versions included — and every running app image. Each entry's golden image is in
  Harbor `golden` with a Harbor Trivy report, an image tag other than `sha256-*` and the DT project `golden/<name>`
  version `<that tag>`, and its verified SLSA provenance names one dhi.io base whose OpenVEX dhi.io still serves.
  Two sources, because Dependency-Track lists no Debian finding (DependencyTrack/dependency-track#6132, `docs/ROADMAP.md`;
  at the time of writing DT lists no finding at all for the golden and app projects):
  - `source="harbor-trivy"` covers OS packages and language packages as Harbor's Trivy scanner sees them: `before` = the
    entries of the artifact's Harbor report (`…/artifacts/<digest>/additions/vulnerabilities`, key
    `application/vnd.security.vulnerability.report; version=1.1`, severity lowercased) — exactly; `after` = those
    entries minus the ones a `not_affected` statement of the VEX applied to that image covers (the DHI OpenVEX of its
    base as in M6, and for running app images the Kubescape runtime OpenVEX as in M7, same coverage rule). Harbor's
    Trivy applies no VEX itself: at the time of writing its reports hold 47 entries for golden python and 82 for golden
    java, of which the DHI OpenVEX states 40 of 41 and 22 of 22 CVE ids `not_affected`.
  - `source="dependency-track"` covers what DT matches (application ecosystems today): `before` = the DT findings of the
    project `<image>` version `<its Harbor tag>` (`suppressed=true`) by `vulnerability.severity`; `after` = those whose
    `analysis.state` is neither `NOT_AFFECTED` nor `FALSE_POSITIVE` and not suppressed.
  Test anchors, per catalog entry, polled up to 300 s: every series present with `golden` = the catalog name; harbor-trivy `before` equals
  the Harbor report; dependency-track `before`/`after` equal DT; harbor-trivy `after` ≤ `before` and ≥ the report entries
  whose CVE id no DHI `not_affected` statement names (name or alias), per severity; and the `after` total is below the
  `before` total whenever an uncontested DHI `not_affected` statement names a report entry's CVE at its version.
- Signed/attested panel feed, metric `harborlab_running_containers{golden, namespace, pod, container, digest, signed,
  attested}` = 1 per running container (any namespace) whose image is a Harbor `golden`/`apps` digest reference with a
  `io.harborlab.golden.name` label; `signed`/`attested` are `"true"`/`"false"`: the cosign signature, and all of the
  CycloneDX, SPDX and SLSA attestations, verify against the build identity (`build-image.yml` for `apps`, `golden.yml`
  or `build-image.yml` for `golden`, refs `main|prd-*`, issuer GitHub Actions). The panel shows the share of
  `signed="true",attested="true"` among them for `$golden`. Test: the series with value 1 equal, as a set, the running
  containers the test lists and verifies with cosign itself (polled up to 300 s). Coverage rule with versions: every
  `supported` catalog entry has at least one running container labelled with its name that is either that golden
  digest or an app image whose verified SLSA provenance names it as its single `oci://` base (today dt-bridge →
  python, hello-java → java); a `deprecated` entry needs none (a container built on it, e.g. the
  `demo:deprecated-base` pod, is in the set like any other); an `eol` entry needs none (admission denies it). The
  signed panel must return data for every name with a `supported` entry; the CVE panel for every catalog name.
- Admission violations panel feed (suggested metric `harborlab_admission_violations_total{golden, policy, action,
  namespace}`, `action` ∈ `deny|warn|audit`, `golden="none"` when the offending image has no label or cannot be read):
  denials count, per golden image of the denied image. Known constraints: a Kyverno 1.19 CEL `Deny` emits no Kubernetes
  Event (checked: a denied Pod left no `PolicyViolation` event) and Kyverno metrics carry no image, so the feed needs its
  own source (e.g. the API server audit log shipped to VictoriaLogs, or an exporter observing admissions); PolicyReport
  `fail`/`warn` results may be added. Test: the panel's value for `$golden` = the label of the running dt-bridge image
  grows within 180 s after the test creates a Pod in namespace `dt-bridge` referencing that digest on GHCR
  (`ghcr.io/…/apps/dt-bridge@sha256:…`), which `workload-registry` denies (asserted from `kubectl apply` stderr).
- Runtime alerts panel feed: Kubescape runtime alerts per golden image of the alerted container (datasource
  `victorialogs`, or `victoriametrics` fed from the same alerts); per-golden attribution is the implementer's (e.g. a
  VictoriaLogs subquery on digests, or a derived metric). Test: the panel's value for the golden image of the
  `task demo:runtime-shell` target grows within 180 s of the task.
- Kubescape alerts → VictoriaLogs (criterion 20): runtime rules must be installed — today `alertCRD.installDefault` is
  `false`, so no `Rules` object and no `RuntimeRuleAlertBinding` exist and node-agent raises nothing; M8 sets it to
  `true` (default rules `default-rules`, binding `all-rules-all-pods`). node-agent's stdout exporter (enabled, the chart
  default) writes one logrus JSON line per alert on the stderr of container `node-agent` (namespace `kubescape`):
  `msg` = alert name, `message` = rule message (e.g. `Unexpected process launched: sh with PID 123`, `Process (sh) was
  executed and is not part of the image`), `RuleID`, `BaseRuntimeMetadata`, `RuntimeProcessDetails`,
  `RuntimeK8sDetails` (`namespace`, `podName`, `containerName`, image), `time`. The collector ships that container's logs
  (namespace `kubescape` not excluded); vlagent parses JSON, maps `message` to `_msg` and `time` to `_time`, and
  VictoriaLogs flattens nested keys with dots. Test query (LogsQL through Grafana): `RuleID:* AND
  RuntimeK8sDetails.namespace:="<ns>" AND RuntimeK8sDetails.podName:="<pod>" AND RuntimeK8sDetails.containerName:="<c>"`;
  a row counts when its time is ≥ the task's start and its text names a shell process (`sh`, `bash`, `dash`, `ash` or
  `busybox`, delimited). The 120 s window starts when `task demo:runtime-shell` starts and includes the task itself.
- `task demo:runtime-shell` (Taskfile at the repository root, run from it through Devbox; uses `.kube/harborlab.yaml`
  itself): runs a shell process non-interactively (no TTY in the test) in a running container of a pod in a namespace
  labelled `harborlab.io/tier=workload` whose image is a Harbor `golden`/`apps` digest reference with a golden label,
  prints on stdout the line `runtime-shell target: <namespace>/<pod>/<container>`, and exits 0 after the exec returned,
  within 120 s (the observability test allows 300 s). The workload images have no shell (DHI runtime bases: `sh` and
  `ls` absent from dt-bridge and hello-java, checked), and Kyverno checks ephemeral container images too; the task and
  the platform must provide a shell-capable governed target whose Kubescape application profile is ready before the task
  starts (R0001 `Unexpected process launched` requires a profile; `learningPeriod` 2m). Every run must raise its own
  alert: `ruleCooldown` (1 h after 1 alert per container and rule, chart default) must not swallow a second run within
  the hour (new container per run, or cooldown settings). CAT-023 (M9) later adds the namespace variable and the
  negative control.
- Policy Reporter UI (criterion 21): `https://policy-reporter.127.0.0.1.nip.io` through the Gateway (local CA), UI v2
  API without login on this local host: `GET /api/config` (`default` or `clusters[0].slug`), then
  `GET /api/<cluster>/namespace-scoped/results?namespaces=<ns>&sources=<source>&policies=<policy>&page=1&offset=50`
  (`items[]` with `namespace` and `policy`; policy-reporter-ui's PolicyResult model has no `source` field, v2.7.3–v2.8.1,
  so the source is proven by the `sources=` filter the UI passes to core, which is case-sensitive). Kyverno 1.19 writes
  its results with sources `KyvernoValidatingPolicy`, `KyvernoImageValidatingPolicy` and `KyvernoMutatingPolicy`
  (checked). Test: for every (namespace, source, policy) of the cluster's namespaced PolicyReports whose source starts
  with `Kyverno` (15 at M8, in `dt-bridge`, `hello-java` and `runtime-demo`), the UI filtered on that namespace, source
  and policy lists a result of that namespace and policy, and the same query with source `harborlab-absent-source`
  lists none (control: the filter is applied).
- Memory (criterion 22): measured exactly as the criterion says, `kubectl top nodes` (metrics-server), 4 samples 20 s
  apart, each ≤ 12288 Mi (12 GiB; criterion 22 was 10 GiB when this was written) for the single node `harborlab-control-plane`, with every Application Synced and Healthy and the
  M8 Applications present (`metrics-server`, `victoria-metrics`, `victoria-logs`, `grafana`, `policy-reporter` plus all
  earlier ones). The test also prints `docker stats` of the node container per sample: the two can disagree
  (metrics-server reports the node's cgroup working set, active page cache included — containerd, Grype DB —,
  `docker stats` the container's usage minus cache); only `kubectl top nodes` is asserted. Measured at M8 on the full
  platform: 10052–10219 Mi on a fresh cluster, peak 10429 Mi after the full suite. Measured before M8: `kubectl top nodes` unavailable (no metrics-server),
  `docker stats` 8.2–8.4 GiB (8.37 GiB when this was written), so M8 has about 1.6 GiB: VictoriaMetrics single ≤ 256Mi,
  VictoriaLogs ≤ 256Mi, collector ≤ 128Mi, Grafana ≤ 256Mi, Policy Reporter core + UI ≤ 128Mi, metrics-server ≤ 64Mi,
  short retention (e.g. 7d) and small PVCs.

M9 interface assumed by `tests/platform/demo_scenarios.bats` (CAT-023, loading `tests/supply-chain/golden.bash`,
`tests/platform/dt.bash` and `tests/platform/grafana.bash`) and `tests/docs/docs.bats` (CAT-023, CAT-025):
- Tools: nothing new (`task`, `kubectl`, `cosign`, `jq`, `yq`, `curl` on the Devbox PATH).
- Demo tasks (Taskfile at the repository root, run from it through Devbox, each using `.kube/harborlab.yaml` itself):
  `demo:unsigned`, `demo:foreign-signer`, `demo:non-golden-base`, `demo:deprecated-base`, `demo:eol-base`,
  `demo:direct-dockerhub`, `demo:root`, `demo:runtime-shell` (M8, kept), `demo:vex`. Each exits 0 only once it has
  observed the platform's reaction documented in `docs/DEMO.md`, non-zero otherwise; stdout and stderr are read merged.
- Admission scenarios (the seven first): Taskfile variable `NAMESPACE` (`task demo:unsigned NAMESPACE=<ns>`); its
  default is a namespace provided by the platform and labelled `harborlab.io/tier=workload`. The task never creates,
  labels or deletes the namespace it is given. It submits one pod (replacing a previous pod of the same name), prints
  first the stdout line `demo:<scenario> target: <namespace>/<pod> image: <image reference as submitted>`, and forwards
  the API server's answer (denial message, `Warning:` lines). Test table (API server text, expected state):
  | Scenario | Reaction | Text the output contains | Image submitted, cross-checked by the test |
  |---|---|---|---|
  | `unsigned` | denied | `Policy workload-image-signature failed: image is not signed by the harborlab build-image workflow` | Harbor `golden/`/`apps/`; `cosign verify` with any identity fails |
  | `foreign-signer` | denied | same as `unsigned` | Harbor; a keyless signature verifies with any identity, none with the build identity |
  | `non-golden-base` | denied | `Policy workload-golden-base failed: image base is not a golden image of the catalog` | Harbor; its SLSA provenance verifies against the build identity and its single `oci://` base is absent from the live ConfigMap `kyverno/golden-images` |
  | `eol-base` | denied | `Policy workload-golden-base failed: image base is an end-of-life golden image` | Harbor; base `eol` in the live ConfigMap |
  | `deprecated-base` | admitted with warning | a `Warning:` line naming `workload-golden-base-deprecated` and `image base is a deprecated golden image` | Harbor; base `deprecated` in the live ConfigMap; the pod exists afterwards, every container image a Harbor digest reference (criterion 11) |
  | `direct-dockerhub` | denied | `Policy workload-registry failed: image is not served from an allowed workload registry` | a Docker Hub reference (host `docker.io`, `index.docker.io`, `registry-1.docker.io` or none) |
  | `root` | denied | `violates PodSecurity "restricted:latest"` | Harbor |
  A denied pod does not exist after the task. Live `deprecated`/`eol` bases are genuine older golden versions (human
  decision, 2026-09-28): `images/catalog.yaml` keeps its lifecycle history — e.g. an older golden python marked
  `deprecated` and another marked `eol`, with their real `released`/`eol` dates — each really built by `golden.yml`,
  never a stand-in (the M4 DHI fixture bases are not catalog entries and do not qualify). The test requires, for
  `deprecated-base` and `eol-base`, that the provenance base digest is an `images/catalog.yaml` entry of that status
  (besides the live ConfigMap), and that `ghcr.io/…/golden/<name>@<that digest>` verifies (signature and SLSA
  provenance) against the golden identity (`golden.yml` or `build-image.yml`, refs `main|prd-*`) with exactly one
  `oci://dhi.io/` base. Criterion 8 still holds (`task catalog:check` green). Tags: `golden/<name>:sha-<commit>` stays
  the build of `images/golden/<name>/Dockerfile` (the current `supported` version, what CAT-005/006/016/017 resolve);
  an older version is pushed to the same repository `golden/<name>` under another tag (e.g. `<version>-sha-<commit>`),
  never `sha-<commit>`. Every catalog entry is replicated into Harbor `golden` with that tag (CAT-021 requires its
  Trivy report and DT project version). The demo images submitted by `deprecated-base`/`eol-base` are built `FROM`
  those golden digests, which the `from-golden` lint rejects outside its documented exclusions (`tests/**`,
  `images/golden/**`, `spike/**`); the lint is not widened for product paths, so their Dockerfiles are test fixtures
  `tests/fixtures/images/demo-deprecated-base/Dockerfile` and `tests/fixtures/images/demo-eol-base/Dockerfile`, written
  by the tester once the catalog holds the genuine entries (`build-image.yml` needs a literal digest-pinned `FROM`):
  the coder first commits the older golden builds and their catalog entries, then asks for these fixtures, then
  publishes them (e.g. `fixtures.yml`, `fixtures/demo-*:e2e`) and replicates them into Harbor. The images must be in
  Harbor `golden`/`apps` (M4 left the fixtures on GHCR only); where they are replicated from is the coder's choice.
  Build identity as in the M4 interface.
- Negative control: in a namespace the test creates without any label (`harborlab-demo-control`), each admission task
  run with `NAMESPACE=harborlab-demo-control` prints its target line in that namespace, draws no denial nor
  `Warning: … workload-…` (nothing reacts there), exits non-zero, and leaves the namespace labels unchanged.
- `demo:runtime-shell`: M8 contract kept (non-interactive shell in a governed workload container, stdout line
  `runtime-shell target: <namespace>/<pod>/<container>`, returns within 120 s); it now also waits for the Kubescape
  alert of its own exec and prints `runtime-shell alert: <alert text>` before exiting 0, non-zero when no alert comes.
  The test requires, through Grafana's `victorialogs` datasource (query of the M8 interface, up to 60 s of ingestion
  after the task returned), an alert naming a shell for that container timestamped between the task's start and its
  exit. Run once, no retry: finding T9 (profile recreated and not yet loaded by node-agent, or not completed within
  120 s) fails the test.
- `demo:vex` (criterion 17 as narrowed): makes dt-bridge convert and upload the DHI VEX of a catalog golden image
  (e.g. by running `golden-from-ghcr` or replaying the Harbor webhook), waits until Dependency-Track reports the VEX
  token `COMPLETED`, then prints `vex accepted: golden/<name>:<tag> token <token>` and exits 0 (non-zero on `FAILED`
  or timeout; the test allows 900 s). The test requires: `<name>` in `images/catalog.yaml`; DT project `golden/<name>`
  version `<tag>` exists; dt-bridge logged, since the task's start, a `DHI VEX uploaded` entry for that image and tag
  with that `token` and the project's `project_uuid` (M6 VEX observables); `GET /api/v1/event/token/<token>` answers
  `COMPLETED` right after the task returned; the output holds no `NOT_AFFECTED` (no finding-level claim while
  DependencyTrack/dependency-track#6132 is open).
- Docs (`tests/docs/docs.bats`, read statically): `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT-MODEL.md`,
  `docs/DEMO.md`, `docs/ROADMAP.md` non-empty.
  - ADRs: `docs/adr/NNNN-<slug>.md`, title on the first `# ` line, sections `## Context`, `## Decision`,
    `## Consequences` (ADR 0001 has them). One distinct ADR per decision, matched on the lowercased title by extended
    regexps (all must match): Kyverno CEL-only `kyverno` + `cel`; `kubescape.*(over|instead of|rather than|replac).*trivy[ -]operator`
    + `falco`; `dependency-track` + `dt-bridge`; `opentofu.*goharbor.*(over|instead of|rather than).*harbor-cli`
    (Decision 8 as changed); `transparent.*mirror` + `trust tier`; `keyless` + `sign`. No ADR title records
    `harbor-cli … over … terraform|opentofu`. An ADR mentioning Grype also mentions Trivy (the divergence risk).
  - English: in `README.md`, `docs/*.md` and `docs/adr/*.md` (fenced code, inline code and link targets ignored), no
    paragraph holds 3 or more French function words making up 10 % or more of its words (partial proof).
  - `README.md`: a heading naming the prerequisites whose section mentions devbox, Docker, `gh`/GitHub CLI, `DHI_TOKEN`,
    `DHI_USERNAME`, `.env` and 16 GiB; a heading naming memory whose section mentions `kubectl top nodes`, working set,
    page cache and 12 GiB (criterion 22); `task up` somewhere.
  - `docs/ROADMAP.md`: the Decision 17 items (air-gap bundle, Gatekeeper + Rego, Buildah, chart relocation as OCI:
    `relocat` + `chart` + `oci`) and the upstream issues kept (`dependency-track#6132`, `#6957`, `kyverno/sdk#125`, as
    `#n` or `/issues/n`).
  - `docs/DEMO.md`: `Taskfile.yml` defines the nine `demo:<scenario>` tasks; per scenario a heading containing
    `demo:<scenario>` whose section (up to the next heading of its level) names the reaction: `workload-image-signature`
    + deny (`unsigned`, `foreign-signer`), `workload-golden-base` + deny (`non-golden-base`; `eol-base` also
    end-of-life/EOL), `workload-golden-base-deprecated` + warning + admit, `workload-registry` + deny, Pod Security +
    `restricted` + deny (`root`), Kubescape + VictoriaLogs or Grafana (`runtime-shell`), Dependency-Track + `COMPLETED`
    + `dependency-track#6132` (`vex`); the file shows `NAMESPACE=` and states that a scenario exits 0 when the
    platform reacts and non-zero otherwise.

Public-repo rules, binding for every test:
- No secret, token, kubeconfig, private key or `.env` content is committed. `DHI_TOKEN` is read
  from the environment only; cluster credentials (Harbor, Grafana, DT API key) are read from their
  Kubernetes Secret into a shell variable at run time and passed via stdin or header file.
- No test prints a secret value: no `set -x`, no `echo` of credentials, `--password-stdin` for
  logins, `-q`/`>/dev/null` on any grep or pickaxe that takes a secret as its pattern.
- Fixtures hold only obviously fake values (`fake-dt-api-key-for-tests`, `example.invalid`).
- Deliberately bad CI fixtures (unpinned action, zizmor finding, detectable token pattern,
  failing Dockerfile or manifest) are generated into `$BATS_TEST_TMPDIR` by the test and never
  committed, so the repository's own scanners and Scorecard stay clean.

## Rows

| ID | Crit | Milestone | Tier | Action | Scenario | File |
|---|---|---|---|---|---|---|
| CAT-000 | — (M0 spike) | M0 | live | create | On the spike kind cluster: a keyless-signed, attested GHCR image replicated into Harbor passes `cosign verify` and `cosign verify-attestation` (CycloneDX, SPDX, SLSA provenance) on its Harbor reference; a pod on that reference is admitted by the spike ImageValidatingPolicy while an unsigned image on the same Harbor project is denied; a pull through the containerd mirror lands in the Harbor proxy cache, and still succeeds with Harbor scaled to 0. | `tests/spike/m0.bats > "replicated image verifies on its Harbor reference"`<br>`tests/spike/m0.bats > "ImageValidatingPolicy admits the replicated image and denies an unsigned one"`<br>`tests/spike/m0.bats > "containerd mirror serves through Harbor proxy cache and falls back upstream"` |
| CAT-001 | 1 | M1 | live | create | From a down state (no kind cluster, no isolated kubeconfig — the closest reproducible stand-in for a clean machine), `devbox run -- task up` exits 0; right after exit every `applications.argoproj.io` is `Synced` and `Healthy`, and each Application's `status.health.lastTransitionTime` and `status.operationState.finishedAt` are at least 60 s before the task's exit time (proves the 60 s stability wait happened). | `tests/platform/lifecycle.bats > "task up exits 0 with every ArgoCD Application Synced and Healthy for 60s"` |
| CAT-002 | 2 | M1 | live | create | `devbox run -- task down` exits 0; `kind get clusters` no longer lists the harborlab cluster and the isolated kubeconfig file no longer exists; a following `task up` exits 0 with every Application Synced and Healthy. | `tests/platform/lifecycle.bats > "task down removes the cluster and the isolated kubeconfig"`<br>`tests/platform/lifecycle.bats > "task up succeeds again after task down"` |
| CAT-003 | 3 | M2 | live | modify | Precondition: Harbor is the ArgoCD Application `harbor`, on CNPG Cluster `harbor-db`. After a first `task harbor:configure`, `task harbor:plan` (`tofu plan -detailed-exitcode`) exits 0 — the plan of the second run is empty — and the second `task harbor:configure` exits 0; the decrypted state (`task harbor:tofu -- show -json`) manages a resource of each category (the 7 projects, the 5 registry endpoints, both replications, the robot, and per governed project an immutable rule, a retention policy, a webhook, deployment security `critical` + vulnerability scanning), so the empty plan is not vacuous. A Harbor API snapshot (projects + metadata, registries, replication policies, robot accounts, immutable rules, retention policies, webhook policies) plus the OpenBao KV version of each robot credential is identical before and after another run, and holds the configuration of the M2 interface; each robot credential stored in OpenBao gets 200 on `GET /v2/` and a wrong one 401. Public-repo invariants: no task output holds the admin password, a robot secret or the DHI token; the state file is git-ignored, untracked, an OpenTofu encrypted payload with `key_provider.openbao.*` metadata (OpenBao `transit/` mounted), with none of those secrets in its bytes; the decrypted state's `harbor_robot_account` has no `secret` and holds no robot secret (all checked with output discarded). | `tests/platform/harbor_configure.bats > "second harbor:configure run has an empty OpenTofu plan for every category"`<br>`tests/platform/harbor_configure.bats > "second harbor:configure run leaves Harbor state unchanged"`<br>`tests/platform/harbor_configure.bats > "OpenTofu state is git-ignored, encrypted by OpenBao Transit and holds no robot secret"` |
| CAT-004 | 4 | M2 | live | create | For each upstream, a pod pulls a small pinned image absent from the node cache (removed with `crictl rmi` in the kind node); the pod runs and, within 240 s (Harbor stores a proxied platform manifest 20–200 s after the pull and never guarantees a tag), the Harbor API returns the artifact whose digest is the image's platform manifest digest for the node architecture (`crane digest --platform linux/<arch>`) in the matching proxy-cache project; the artifact is never looked up by tag. Each test image shares no layer (`rootfs.diff_ids`) with any image on the node, compared against the node's layer set captured before the pull, because containerd does not fetch a layer it already holds and Harbor then never caches the artifact (the dhi.io config cannot be read without credentials or without going through Harbor, which would itself fill the cache, so the pulled image's layers are compared after the pull). Then Harbor is scaled to 0 (ArgoCD automated sync paused), all five images are removed from the node again, and their pods re-pull and run through the upstream fallback; Harbor and sync are restored in teardown. dhi.io refuses anonymous pulls: its proxy case relies on the credential configured in Harbor, and its pods carry `imagePullSecrets: [dhi-pull]`, a `kubernetes.io/dockerconfigjson` Secret for `dhi.io` owned by an ExternalSecret reading OpenBao `platform/dhi` (asserted before use), which only the upstream fallback uses; the test never reads `DHI_TOKEN`. | `tests/platform/registry_mirror.bats > "docker.io pull is served through its Harbor proxy cache"`<br>`tests/platform/registry_mirror.bats > "quay.io pull is served through its Harbor proxy cache"`<br>`tests/platform/registry_mirror.bats > "ghcr.io pull is served through its Harbor proxy cache"`<br>`tests/platform/registry_mirror.bats > "registry.k8s.io pull is served through its Harbor proxy cache"`<br>`tests/platform/registry_mirror.bats > "dhi.io pull is served through its Harbor proxy cache"`<br>`tests/platform/registry_mirror.bats > "pulls fall back upstream when Harbor is scaled to 0"` |
| CAT-005 | 5 | M3 | unit, live | create | Unit: `golden.yml` triggers on `push` to `main` with `paths` listing `images/golden/**`. Live, for the branch of `GOLDEN_REF` or the checked-out branch (the PRD branch until the merge, `main` after): the latest successful `golden.yml` run on that branch at a commit in the checked-out history that contains the last change to `images/golden` (via `gh api`) published `ghcr.io/<owner>/harborlab/golden/{python,java}:sha-<commit>`; on its digest `cosign verify` and `cosign verify-attestation --type cyclonedx`, `--type spdxjson`, `--type slsaprovenance1` pass with `--certificate-oidc-issuer https://token.actions.githubusercontent.com`, an identity regexp bound to this repository's `golden.yml` (or `build-image.yml` called by it) on that ref and the workflow-SHA extension equal to the commit; the SBOMs are non-empty and the provenance records the commit; another repository's identity and this repository's `spike.yml` identity fail; that run has, for each image, its `Verify DHI base signature` step concluded `success`, and the dhi.io base digest recorded in the SLSA provenance equals the digest pinned in `images/golden/<name>/Dockerfile` at that commit and verifies against DHI's public key (`https://dhi.io/keyring/latest.pub`), which the golden image itself does not. | `tests/ci/golden_workflow.bats > "golden workflow publishes on pushes to main touching images/golden"`<br>`tests/supply-chain/golden_images.bats > "golden python is signed with CycloneDX, SPDX and SLSA attestations by this repo's workflow"`<br>`tests/supply-chain/golden_images.bats > "golden java is signed with CycloneDX, SPDX and SLSA attestations by this repo's workflow"`<br>`tests/supply-chain/golden_images.bats > "golden image verification fails against a foreign identity"`<br>`tests/supply-chain/golden_images.bats > "golden build verified the DHI base signature"`<br>helper `tests/supply-chain/golden.bash` |
| CAT-006 | 6 | M3 (golden), M5 (apps) | live | modify | Golden (M3): the test runs the Harbor replication `golden-from-ghcr` through the admin API, polls it while in progress and requires it to end `Succeed` (or `Success`); the images selected as in CAT-005 are in Harbor `golden` with their GHCR digest, and the same signature + CycloneDX + SPDX + SLSA verification (same identity, workflow SHA, non-empty SBOMs, provenance commit) passes on `harbor.127.0.0.1.nip.io/golden/{python,java}@<digest>` (local CA trusted) while foreign identities fail. Apps (M5): the app builds selected as in CAT-007 are resolved first, then `apps-from-ghcr` is run the same way; `apps/{dt-bridge,hello-java}@<GHCR digest>` are in Harbor and the CAT-007 verification (signature, CycloneDX, SPDX, SLSA against `build-image.yml` only, workflow SHA, provenance commit and catalog base) passes on `harbor.127.0.0.1.nip.io/apps/<app>@<digest>` while the app's caller identity and foreign identities fail. | `tests/supply-chain/harbor_replicated.bats > "replicated golden images verify on their Harbor reference"`<br>`tests/supply-chain/harbor_replicated.bats > "replicated app images verify on their Harbor reference"` (M5)<br>helpers `tests/supply-chain/golden.bash`, `tests/supply-chain/apps.bash` |
| CAT-007 | 7 | M5 | unit, live | create | Unit: each app workflow (`.github/workflows/{dt-bridge,hello-java}.yml`) builds on pushes to `main` touching `apps/<app>/**` and is a single job made of its only `uses:` line to `build-image.yml` plus the inputs `image`/`context` = `apps/<app>` (no step, no secret, no permission beyond `contents: read`, `packages: write`, `id-token: write`, no cosign/syft/trivy/grype/notation/sigstore/attest/sbom/provenance anywhere in its keys or values); each app Dockerfile has every `FROM` on a `supported` catalog golden digest (or an earlier stage), its final stage directly on golden python (dt-bridge) or java (hello-java), and no security instruction (certificate copy, CA install, signing or scanning tool, root `USER`); `build-image.yml` runs a named, unconditional, blocking Trivy step with `--vex oci` before signing (an M3 invariant: it passes before M5 and cannot fail on the coder's revert). Live: for each app, the latest successful `<app>.yml` run of the branch at a commit holding the last change to the app published `apps/<app>:sha-<commit>`, whose digest verifies (signature, CycloneDX, SPDX, SLSA, non-empty SBOMs, workflow SHA) against the `build-image.yml` identity only (not the app's caller workflow, not a foreign one), with a provenance recording the commit and exactly one base, the final `FROM` digest of the app Dockerfile, a `supported` catalog entry; that run's Trivy step (named as in `build-image.yml` at that commit) concluded `success`. | `tests/ci/app_contract.bats > "app workflows are a single uses line to build-image.yml"`<br>`tests/ci/app_contract.bats > "app Dockerfiles only need FROM a golden image"`<br>`tests/ci/app_contract.bats > "build-image.yml scans with Trivy using VEX from OCI"`<br>`tests/supply-chain/app_images.bats > "app images are signed and attested by build-image.yml"`<br>`tests/supply-chain/app_images.bats > "app build ran the VEX-aware Trivy scan"`<br>helpers `tests/supply-chain/golden.bash`, `tests/supply-chain/apps.bash` |
| CAT-D04 | Decision 4 (supports 5, 7) | M3 | unit, live | create | Live: Argo CD Application `trust-manager` is Synced and Healthy and installs the trust-manager chart; Bundle `harborlab-trust` exists and never reads the CA key (`tls.key`, `includeAllKeys`). In a namespace labelled `harborlab.io/tier=workload`, created by the test, ConfigMap `harborlab-trust` appears within 120 s; its PEM key `ca.crt` holds a certificate whose SHA-256 fingerprint equals that of the local CA (public `tls.crt` of `cert-manager/harborlab-ca`, also the CA of the Harbor endpoint's certificate) and no private key; its PKCS#12 key `truststore.p12` (password-less) holds the same fingerprint; the PEM alone lets curl trust `https://harbor.127.0.0.1.nip.io`. An unlabelled namespace, created alongside, gets no copy, and no namespace without the label holds one. Unit: the golden Dockerfiles `COPY`/`ADD` no certificate, install none with `RUN`, and set a non-root `USER` in their final stage (an invariant already true at M3: it guards against re-baking the CA and cannot fail on the coder's revert). | `tests/platform/trust_bundle.bats > "trust-manager is deployed by Argo CD with a bundle of the local CA public certificate"`<br>`tests/platform/trust_bundle.bats > "local CA bundle reaches workload namespaces as PEM and PKCS#12"`<br>`tests/platform/trust_bundle.bats > "local CA bundle is not written to namespaces without the workload label"`<br>`tests/ci/golden_dockerfiles.bats > "golden Dockerfiles bake no CA and run as a non-root user"` |
| CAT-008 | 8 | M3 | unit | create | `task catalog:validate` accepts `tests/fixtures/catalog/valid.yaml` (control) and rejects, naming the field, `missing-digest.yaml`, `invalid-status.yaml` (status outside `supported\|deprecated\|eol`), `malformed-digest.yaml` and `invalid-date.yaml` (2027-02-30); `images/catalog.yaml` validates and holds a supported python and java entry (several entries may share a name — versions, lifecycle history — and every check below is per entry, keyed by digest, never by name); `task catalog:generate` in a temp copy of the working tree reproduces the committed Kyverno params ConfigMap `policies/params/golden-images.yaml` and doc `docs/golden-images.md` byte for byte, the ConfigMap maps every entry `sha256.<hex>` to its status and the doc has a row per entry; in a temp copy, `task catalog:check` passes (control), then fails after an entry's status is changed without regenerating, leaves the ConfigMap untouched, and passes again after `catalog:generate`, whose ConfigMap carries the new status; the platform CI workflow runs `task catalog:check` in a blocking step on every `pull_request`. | `tests/ci/catalog.bats > "catalog validation rejects invalid entries"`<br>`tests/ci/catalog.bats > "generated ConfigMap and doc match the catalog"`<br>`tests/ci/catalog.bats > "drift check fails when generated files are out of date"`<br>`tests/ci/catalog.bats > "platform CI runs the catalog drift check on pull requests"`<br>fixtures `tests/fixtures/catalog/{valid,missing-digest,invalid-status,malformed-digest,invalid-date}.yaml` |
| CAT-009 | 9 | M4 | unit, e2e | create | `kyverno test` through `tests/kyverno/run.sh` (with `--registry`, against real fixture images published by the repo's fixtures workflow, tags pinned and image metadata fetched from the registry at run time, E2E params in the context): `fail` of the rule's own policy for unsigned and foreign signer (`workload-image-signature`), non-Harbor registry (`workload-registry`, compliant image outside the allow-list), EOL base and base digest absent from the catalog (`workload-golden-base`), no SBOM attestation (`workload-image-signature`), missing OCI/`io.harborlab.*` labels (`workload-image-labels`), each case also passing the policies it satisfies; `pass` of every workload policy for the compliant golden-path image; the MutatingPolicy `workload-pod-security` labels a workload Namespace Pod Security `restricted`. Chainsaw on an ephemeral kind cluster: each of those pods, plus a pod running as root, is rejected in a `harborlab.io/tier=workload` namespace with the policy name and message of the M4 interface (Pod Security: `violates PodSecurity "restricted:latest"`, after the platform labelled the namespace), and the compliant pod is admitted without warning with a `pass` from every workload policy in its PolicyReport. PSS `restricted` is native PSA, which `kyverno test` does not evaluate: it is proven by Chainsaw only. | `tests/kyverno/workload/image-signature/kyverno-test.yaml > unsigned, foreign-signer, no-sbom (fail); compliant and the others (pass)`<br>`tests/kyverno/workload/registry/kyverno-test.yaml > non-harbor-registry (fail); compliant and the others (pass)`<br>`tests/kyverno/workload/golden-base/kyverno-test.yaml > eol-base, unknown-base (fail); compliant, deprecated-base and the others (pass)`<br>`tests/kyverno/workload/image-labels/kyverno-test.yaml > missing-labels (fail); compliant and the others (pass)`<br>`tests/kyverno/workload/pod-security/kyverno-test.yaml > new-workload namespace (patched)`<br>harness `tests/kyverno/run.sh`<br>`tests/chainsaw/workload/unsigned/chainsaw-test.yaml`<br>`tests/chainsaw/workload/foreign-signer/chainsaw-test.yaml`<br>`tests/chainsaw/workload/non-harbor-registry/chainsaw-test.yaml`<br>`tests/chainsaw/workload/eol-base/chainsaw-test.yaml`<br>`tests/chainsaw/workload/unknown-base/chainsaw-test.yaml`<br>`tests/chainsaw/workload/no-sbom/chainsaw-test.yaml`<br>`tests/chainsaw/workload/missing-labels/chainsaw-test.yaml`<br>`tests/chainsaw/workload/pss-restricted/chainsaw-test.yaml`<br>`tests/chainsaw/workload/compliant/chainsaw-test.yaml`<br>fixtures (shared by the workload suites) `tests/kyverno/workload/{values,context}.yaml`, `tests/kyverno/workload/resources/{pods,namespace}.yaml`, `tests/kyverno/workload/patched/namespace.yaml`, `tests/chainsaw/workload/*/pod.yaml`, `tests/chainsaw/params/{golden-images,registries}.yaml`, `tests/fixtures/images/{compliant,missing-labels,deprecated-base,eol-base,unknown-base}/Dockerfile` |
| CAT-010 | 10 | M4 | unit, e2e | create | `kyverno test`: a pod built on a base the E2E catalog marks `deprecated` fails `workload-golden-base-deprecated` (Kyverno CEL policies report `fail`, never `warn`; that policy's actions are `[Warn, Audit]`, checked by CAT-013) and passes `workload-golden-base` and the other workload policies. Chainsaw: in a workload namespace the pod is admitted, `kubectl apply` stderr carries a `Warning:` naming `workload-golden-base-deprecated` with its deprecation message, and the pod's PolicyReport holds that policy's `fail` result next to a `pass` from `workload-golden-base`. | `tests/kyverno/workload/golden-base-deprecated/kyverno-test.yaml > deprecated-base (fail); compliant and the others (pass)`<br>`tests/kyverno/workload/{golden-base,image-signature,image-labels,registry}/kyverno-test.yaml > deprecated-base (pass)`<br>`tests/chainsaw/workload/deprecated-base/chainsaw-test.yaml` (+ `pod.yaml`) |
| CAT-011 | 11 | M4 | e2e | create | Chainsaw: a compliant pod referencing `…/fixtures/compliant:e2e` is admitted and its stored `spec.containers[0].image` ends with `@sha256:<digest the tag serves>` (read with `crane digest` at test time). | `tests/chainsaw/workload/digest-mutation/chainsaw-test.yaml` (+ `pod.yaml`) |
| CAT-012 | 12 | M4 | unit, e2e | create | `kyverno test`: in a platform namespace a pod from a registry outside the allow-list (`public.ecr.aws`) fails `platform-registry-allow-list` (Audit), allow-listed ones pass; the Kyverno, Cilium and Argo CD images pass `platform-vendor-signatures`, and an Argo CD release published before Argo CD signed its images (`v2.4.0`) fails it (negative control). Chainsaw: in a platform-tier namespace the off-list pod is admitted and its PolicyReport holds a `fail` result, the allow-listed one a `pass`; pods running the Kyverno, Cilium and Argo CD vendor images get a `pass` from the vendor-signature policy and the unsigned Argo CD release a `fail`; with `kube-system`, `cilium`, `argocd` and `kyverno` labelled platform, an off-list pod in each produces no PolicyReport while the same pod in a platform namespace (control) is reported. Docs: `docs/THREAT-MODEL.md` names the four bootstrap namespaces as an explicit exclusion. | `tests/kyverno/platform/registry-allow-list/kyverno-test.yaml > off-list-registry (fail); allow-listed-registry, vendor images (pass)`<br>`tests/kyverno/platform/vendor-signatures/kyverno-test.yaml > vendor-kyverno, vendor-cilium, vendor-argocd (pass); vendor-unsigned (fail)`<br>`tests/chainsaw/platform/off-list-registry/chainsaw-test.yaml`<br>`tests/chainsaw/platform/vendor-signatures/chainsaw-test.yaml`<br>`tests/chainsaw/platform/bootstrap-excluded/chainsaw-test.yaml`<br>`tests/docs/docs.bats > "threat model documents the bootstrap namespace exclusion"`<br>fixtures (shared by the platform suites) `tests/kyverno/platform/{values,context}.yaml`, `tests/kyverno/platform/resources/pods.yaml`, `tests/chainsaw/platform/off-list-registry/pods.yaml`, `tests/chainsaw/platform/vendor-signatures/pods.yaml`, `tests/chainsaw/platform/bootstrap-excluded/{namespaces,pods,control}.yaml` |
| CAT-013 | 13 | M4 | unit | create | The policy workflow triggers on `pull_request` (no branch filter) with `paths` absent or covering `policies/**`; blocking jobs run `tests/kyverno/run.sh` (`kyverno test --registry` on `tests/kyverno`) and, on a kind cluster created in the job with Kyverno installed by Helm and `policies/workload`, `policies/platform` and the E2E params applied, `chainsaw test` on `tests/chainsaw`; the `kyverno` CLI (≥ 1.19) and `chainsaw` are on the Devbox PATH. Each deny/warn case of criteria 9–10 (8 deny + 1 warn) has a Chainsaw case directory, and each except PSS `restricted` a `kyverno test` `fail` of its policy in that policy's own suite; every suite under `tests/kyverno` loads exactly one policy and each M4 policy has exactly one suite; the policies are the M4 interface's CEL types, names and actions (deny policies `Deny`, the deprecation policy `Warn` + `Audit` without `Deny`, platform policies `Audit` without `Deny`), and nothing under `policies/` is a `ClusterPolicy`/`Policy`. The E2E params keep every production `supported` entry unchanged, change no production entry (production `deprecated`/`eol` versions may be absent) and only add fixture entries (`deprecated`/`eol` digests absent from `images/catalog.yaml`, the GHCR fixtures prefix); the production workload allow-list is exactly Harbor `golden`/`apps`; the `kyverno test` contexts equal the E2E params and mock no image, and every suite reads its tier's context; each fixture base has the status its case stands for. "Every PR" over time is not observable; the trigger wiring and the passing suites (CAT-009/010) are. | `tests/ci/policy_ci.bats > "policy workflow runs kyverno test and Chainsaw on PRs touching policies"`<br>`tests/ci/policy_ci.bats > "every deny and warn case of criteria 9-10 has a kyverno test and a Chainsaw case"`<br>`tests/ci/policy_ci.bats > "E2E params extend the production params with fixture-only entries"` |
| CAT-014 | 14 | M3 | unit | create | `task lint -- <dir>` (the task the platform CI runs) on fixture git repositories generated in `$BATS_TEST_TMPDIR`: a clean baseline passes with no `FAILED` line (control); each fixture adds one defect and the lint exits non-zero with `FAILED <check>` for that check: zizmor (template injection of the PR title in `run:`), `pinned-actions` (`actions/checkout@v7.0.1`), gitleaks (fake GitHub token committed), hadolint (DL3000 relative `WORKDIR`), `trivy-config` (privileged Pod, HIGH), kube-linter (Deployment selector matching none of its pods), `from-golden` (`FROM docker.io/library/python`, and `FROM` a golden digest marked `eol` in the fixture catalog); `task lint` exits 0 on the repository itself; the platform CI runs `task lint` in a blocking step of a `fetch-depth: 0` job on every `pull_request`. The criterion does not say whether a `deprecated` base passes this rule: not asserted. | `tests/ci/platform_lint.bats > "platform lint passes on a clean fixture"`<br>`tests/ci/platform_lint.bats > "zizmor finding fails the lint"`<br>`tests/ci/platform_lint.bats > "action not pinned by SHA fails the lint"`<br>`tests/ci/platform_lint.bats > "detected secret fails the lint"`<br>`tests/ci/platform_lint.bats > "hadolint error fails the lint"`<br>`tests/ci/platform_lint.bats > "Trivy HIGH misconfiguration fails the lint"`<br>`tests/ci/platform_lint.bats > "kube-linter error fails the lint"`<br>`tests/ci/platform_lint.bats > "FROM outside supported golden images fails the lint"`<br>`tests/ci/platform_lint.bats > "platform lint passes on the repository"`<br>`tests/ci/platform_lint.bats > "platform CI runs the lint on pull requests"` |
| CAT-015 | 15 | M5 | live | create | For each app: Argo CD Application `<app>` is Synced and Healthy and manages Deployment `<app>` in namespace `<app>`, labelled `harborlab.io/tier=workload` and enforcing Pod Security `restricted`; the Deployment is fully available and its pods Running and Ready; every pod image is a Harbor `golden`/`apps` digest reference and the app container runs `harbor.127.0.0.1.nip.io/apps/<app>@sha256:…`, whose digest verifies with cosign against the `build-image.yml` admission identity with a SLSA provenance naming exactly one base, a `supported` catalog golden image. Live admission, proven at test time: a server dry-run of a pod with the labels and exact spec of the running app pod (same Harbor digest) in its namespace is admitted without warning, while the same spec with the digest from GHCR is denied by `workload-registry` (control); every workload policy is served by a Kyverno webhook reached by dry-runs whose rules and namespace/object selectors match that pod in that namespace, with `failurePolicy: Fail` for the four Deny policies (`workload-golden-base-deprecated` is Warn/Audit: no warning). PolicyReport `pass` results of the Deny policies are eventual (hourly background scan; a recreated pod gets only Audit results at admission) and not asserted. The app answers through its Service on port 8080 (dt-bridge `GET /healthz` → `{"status": "ok"}`, hello-java `GET /` → 200). Decision 4 at runtime: the container mounts ConfigMap `harborlab-trust` at `/etc/harborlab-trust`; Python's default TLS context in dt-bridge (`SSL_CERT_FILE`) holds the local CA; the JVM of hello-java uses `/etc/harborlab-trust/truststore.p12` as a PKCS12 trust store (`JAVA_TOOL_OPTIONS`). | `tests/platform/golden_path_apps.bats > "dt-bridge runs admitted in a workload namespace, deployed by ArgoCD"`<br>`tests/platform/golden_path_apps.bats > "hello-java runs admitted in a workload namespace, deployed by ArgoCD"` |
| CAT-016 | 16 | M6 | live | create | For `apps/hello-java` (build resolved as in CAT-007) then `golden/python` (as in CAT-005): the test runs the Harbor replication `apps-from-ghcr` / `golden-from-ghcr` through the admin API (the image is then in Harbor at tag `sha-<commit>`), verifies the image's CycloneDX attestation with `cosign verify-attestation --type cyclonedx` against the build identity on its Harbor digest, then within 300 s of the replication's end Dependency-Track holds project `<harbor project>/<repository>` version `sha-<commit>` whose `lastBomImport` is not older than the replication start and whose component purls equal the attested SBOM's (normalised; the attested SBOM, not a regenerated one); no DT version of that project is a `sha256-*` referrers tag. DT API key read from its cluster Secret into a variable and sent on stdin, never printed. | `tests/platform/dt_sbom_upload.bats > "replicated app image SBOM lands in Dependency-Track as attested"`<br>`tests/platform/dt_sbom_upload.bats > "replicated golden image SBOM lands in Dependency-Track as attested"`<br>helpers `tests/platform/dt.bash`, `tests/supply-chain/golden.bash`, `tests/supply-chain/apps.bash` |
| CAT-017 | 17 | M6 | live | modify | For golden `python` (build as in CAT-005), the DHI base is read from its verified SLSA provenance and the attested CycloneDX SBOM from its verified attestation; the test logs in to dhi.io (`DHI_USERNAME`, `DHI_TOKEN` on stdin, throwaway `DOCKER_CONFIG`), takes the latest OpenVEX attestation among the OCI referrers of the DHI platform manifest matching the golden image and requires a `not_affected` statement covering an attested component (non-vacuous), runs `golden-from-ghcr`, then reads dt-bridge's `DHI VEX uploaded` log entry for project `golden/python` version `sha-<commit>` (see « VEX observables »): the uploaded VEX targets only attested SBOM components that are components of the DT project (Debian source-package products resolved to their binary packages), converts every uncontested covering statement with the mapped justification and the vendor author, label, notes and impact statement in the detail, was accepted for that DT project version, and its DT token reaches `COMPLETED` within 600 s. Guard: every DT finding covered by a DHI statement shows `NOT_AFFECTED` with the mapped `analysisJustification` and vendor details. **Partial proof**: the finding-level `NOT_AFFECTED` is not proven while DT lists no Debian finding (DT 5.1 ignores the `upstream=` qualifier, DependencyTrack/dependency-track#6132, #6957, `docs/ROADMAP.md`); the guard proves it automatically once DT matches source packages. Conversion logic itself is covered by CAT-019. | `tests/platform/dt_vex.bats > "dt-bridge converts DHI not_affected statements to a CycloneDX VEX that Dependency-Track accepts"`<br>helpers `tests/platform/dt.bash`, `tests/supply-chain/golden.bash`, `tests/supply-chain/apps.bash` |
| CAT-018 | 18 | M7 | unit, live | create | Live: Argo CD Application `kubescape` is Synced and Healthy and the Kubescape storage APIService is Available; `hello-java` is restarted so Kubescape observes its container from the start; the running digest's Harbor tag names the DT project `apps/hello-java` version `sha-<commit>` and its CycloneDX attestation is verified (build-image.yml identity at that commit). Within 1200 s the `OpenVulnerabilityExchangeContainer` of that container instance (`kubescape.io/instance-id`) exists with at least one `not_affected` statement covering an attested component uncontested at runtime (non-vacuous), and dt-bridge's `Kubescape VEX uploaded` entry for that document and `spec.version` carries the running digest, a token and the DT project's uuid; the uploaded VEX is the conversion of the runtime `not_affected` statements on attested SBOM components that are DT components (mapped justification, `kubescape.io`, label and impact statement in the detail), never marks `not_affected` a package Kubescape reports `affected`, misses no uncontested pair, and its DT token reaches `COMPLETED`. Guard: every DT finding covered by an uncontested runtime `not_affected` statement shows `NOT_AFFECTED` with `CODE_NOT_PRESENT` and the Kubescape texts. RBAC: the dt-bridge ServiceAccount can `get`/`list` those documents in `kubescape` and nothing more (no write, no cluster-wide list, no Secret, ConfigMap or other Kubescape resource). Unit: Docker Hub references (`docker.io`, `index.docker.io`, `registry-1.docker.io`, short names, `docker://`, Kubescape `pkg:oci` purls with an escaped or plain `repository_url`) normalise to one `docker.io/library/nginx` reference, Harbor references and purls to `apps/hello-java` with their digest or tag, a registry with a port is kept, non-images raise `ValueError`; the shared converter does not emit `not_affected` for a component whose own package Kubescape reports `affected` (`libssl3t64` under an `openssl` binary statement). **Partial proof**: the finding-level `NOT_AFFECTED` is not proven while DT lists no finding a runtime statement covers: DT has no Debian finding (DependencyTrack/dependency-track#6132, `docs/ROADMAP.md`) and `apps/hello-java` had no finding at all when this was written; the guard proves it once DT reports one. | `tests/platform/runtime_vex.bats > "Kubescape runtime OpenVEX is applied in Dependency-Track"`<br>`tests/platform/runtime_vex.bats > "dt-bridge reads Kubescape VEX documents with read-only access"`<br>`apps/dt-bridge/tests/test_vex.py::test_kubescape_image_reference_is_normalised`<br>`apps/dt-bridge/tests/test_vex.py::test_kubescape_image_reference_rejects_non_image`<br>`apps/dt-bridge/tests/test_vex.py::test_kubescape_affected_package_is_not_marked_not_affected`<br>fixture `apps/dt-bridge/tests/fixtures/kubescape-openvex.json`<br>helpers `tests/platform/dt.bash` (shared with CAT-017), `tests/supply-chain/golden.bash`, `tests/supply-chain/apps.bash` |
| CAT-019 | 19 | M6 | unit | create | pytest with fixed fixtures (real-shaped Sigstore v0.3 bundles of CycloneDX and SPDX attestations with fake signature and certificate, a syft-shaped CycloneDX SBOM with Debian binary packages carrying `upstream`, a DHI-shaped OpenVEX document with repeated products, source-package names, every justification, an impact-statement-only and an `under_investigation` statement, fake DT API key `fake-dt-api-key-for-tests`): SBOM extracted unchanged from the bundle, a non-CycloneDX predicate and malformed bundles rejected with `AttestationError`; OpenVEX `not_affected` → CycloneDX VEX `not_affected` on exactly the SBOM components its products cover (source-package and version matching, unique bom-refs from the SBOM), justification mapped (none for `vulnerable_code_cannot_be_controlled_by_adversary`) and vendor text in the detail, unknown status and malformed documents rejected with `VexConversionError`, OpenVEX vocabulary read only in `vex.py` (Decision 14); DT client uploads BOM and VEX with the documented request shape and raises typed errors on 401, 5xx and timeout without leaking the key (`httpx.MockTransport` at the transport boundary). `ruff check` and `ruff format --check` pass on `apps/dt-bridge`, and a blocking CI job runs pytest and both ruff checks on pull requests touching it. | `apps/dt-bridge/tests/test_sbom.py::test_extracts_cyclonedx_predicate_from_attestation`<br>`apps/dt-bridge/tests/test_sbom.py::test_rejects_non_cyclonedx_predicate`<br>`apps/dt-bridge/tests/test_sbom.py::test_rejects_malformed_attestation`<br>`apps/dt-bridge/tests/test_vex.py::test_not_affected_becomes_cyclonedx_not_affected`<br>`apps/dt-bridge/tests/test_vex.py::test_vendor_justification_is_mapped`<br>`apps/dt-bridge/tests/test_vex.py::test_unknown_status_is_rejected`<br>`apps/dt-bridge/tests/test_vex.py::test_malformed_document_is_rejected`<br>`apps/dt-bridge/tests/test_vex.py::test_openvex_conversion_is_isolated_in_vex_module`<br>`apps/dt-bridge/tests/test_dt_client.py::test_upload_sends_bom_to_project_version`<br>`apps/dt-bridge/tests/test_dt_client.py::test_upload_vex_sends_vex_to_project_version`<br>`apps/dt-bridge/tests/test_dt_client.py::test_upload_raises_on_unauthorized`<br>`apps/dt-bridge/tests/test_dt_client.py::test_upload_raises_on_server_error`<br>`apps/dt-bridge/tests/test_dt_client.py::test_upload_raises_on_timeout`<br>`tests/ci/python_lint.bats > "ruff check and format pass on dt-bridge"`<br>`tests/ci/python_lint.bats > "dt-bridge pytest and ruff run on pull requests touching the app"`<br>fixtures `apps/dt-bridge/tests/fixtures/{cyclonedx-sbom,cyclonedx-attestation.sigstore,spdx-attestation.sigstore,openvex-document,openvex-unknown-status}.json` |
| CAT-020 | 20 | M8 | live | create | Grafana serves the VictoriaLogs datasource `victorialogs` (plugin `victoriametrics-logs-datasource`). `task demo:runtime-shell` is run (timeout 120 s) and exits 0 printing `runtime-shell target: <namespace>/<pod>/<container>`; the target namespace is labelled `harborlab.io/tier=workload` and the container runs a Harbor digest image. Within 120 s of the task's start, Grafana's `/api/ds/query` on `victorialogs` (LogsQL on the flattened node-agent alert: `RuleID`, `RuntimeK8sDetails.{namespace,podName,containerName}`) returns a Kubescape runtime alert for that container, timestamped after the task's start, whose text names a shell process. Grafana admin credentials read from `observability/grafana-admin`, sent on stdin, never printed. | `tests/platform/runtime_alert.bats > "runtime shell alert is visible in Grafana through VictoriaLogs within 2 minutes"`<br>helper `tests/platform/grafana.bash` |
| CAT-021 | 21 | M8 | live | create | Grafana datasources `victoriametrics` and `victorialogs`; dashboard uid `image-posture` (title "image posture") with a `golden` variable (`label_values(<selector>, golden)` on `victoriametrics`) listing every distinct `images/catalog.yaml` name (a golden image is a catalog name, the `io.harborlab.golden.name` label, whatever its versions), and four panels (titles matching `cve`, `signed`, `admission`, `runtime`) filtered by `$golden`. Events made by the test: a Pod referencing the running dt-bridge digest on GHCR is denied by `workload-registry` in namespace `dt-bridge`, and `task demo:runtime-shell` runs; within 180 s the admission panel grows for the denied image's golden image and the runtime panel for the shell target's. The CVE panel returns data for every catalog name, the signed panel for every name with a `supported` entry. Truth anchors (M8 interface), for every catalog entry (name, version, digest; `supported`, `deprecated` and `eol` alike): `harborlab_image_vulnerabilities` of `golden/<name>@<catalog digest>` has every (source, vex, severity) series, harbor-trivy `before` equals the Harbor Trivy report, dependency-track `before`/`after` equal DT's findings, harbor-trivy `after` lies between the entries no DHI `not_affected` statement names (DHI OpenVEX of the base read from dhi.io with `DHI_USERNAME`/`DHI_TOKEN`) and `before`, and drops below `before` when DHI covers a reported CVE at its version; `harborlab_running_containers` equals the running golden/apps containers the test verifies with cosign (signature + CycloneDX + SPDX + SLSA), with, for every `supported` entry, at least one running container that is that golden digest or an app whose verified SLSA provenance names it as its single base; `deprecated` entries need none (a running one is in the set like any other), `eol` entries none (denied at admission). Policy Reporter UI API (`policy-reporter.127.0.0.1.nip.io`), filtered with `sources=<source>` (its result items carry no source), lists for every (namespace, source, policy) of the cluster's namespaced PolicyReports with a `Kyverno*` source a result of that namespace and policy; the same query with an absent source lists nothing (control). | `tests/platform/observability.bats > "image posture dashboard shows every metric per golden image"`<br>`tests/platform/observability.bats > "Policy Reporter UI lists Kyverno PolicyReports"`<br>helpers `tests/platform/grafana.bash`, `tests/platform/dt.bash`, `tests/supply-chain/golden.bash` |
| CAT-022 | 22 | M8 | live | create | Every Argo CD Application is Synced and Healthy and the M8 ones (`metrics-server`, `victoria-metrics`, `victoria-logs`, `grafana`, `policy-reporter`) exist next to the earlier ones; APIService `v1beta1.metrics.k8s.io` is Available; `kubectl top nodes` (working set, active page cache included) reports the single node `harborlab-control-plane` at most 12288 Mi (12 GiB) in each of 4 samples 20 s apart. `docker stats` of the node is printed beside each sample, not asserted (it can disagree with metrics-server; see M8 interface). | `tests/platform/memory_budget.bats > "cluster memory stays within 12 GiB"` |
| CAT-023 | 23 | M9 | unit, live | modify | Live (M9 interface): each of `task demo:unsigned`, `foreign-signer`, `non-golden-base`, `deprecated-base`, `eol-base`, `direct-dockerhub`, `root` (default workload namespace), `runtime-shell` and `vex` exits 0 on the running platform, and the reaction is cross-checked: the API server text of the policy (or Pod Security) in the output, a denied pod absent, the deprecated pod admitted on Harbor digests with its warning, the submitted image of the right kind (unsigned: no signature; foreign-signer: signed, not by the build identity; bases absent/`eol`/`deprecated` in the live `kyverno/golden-images` per their verified SLSA provenance, and for `eol-base`/`deprecated-base` a genuine older golden build: an `images/catalog.yaml` entry of that status whose `ghcr.io/…/golden/<name>@<digest>` verifies (signature, SLSA provenance with one dhi.io base) against the golden identity; Harbor except direct-dockerhub); runtime-shell prints the alert it saw and VictoriaLogs (through Grafana) holds a shell alert for its container dated between the task's start and exit, run once without retry (T9 fails it); vex prints `golden/<name>:<tag>` and a DT token whose `DHI VEX uploaded` entry names that project version and which is `COMPLETED` at the task's return, with no `NOT_AFFECTED` claim. Negative control: the seven admission tasks run with `NAMESPACE=` a test namespace without `harborlab.io/tier=workload` reach their admission step, draw no reaction, exit non-zero and leave the namespace labels unchanged. Unit: `Taskfile.yml` defines the nine tasks and `docs/DEMO.md` documents each with its reaction, the `NAMESPACE` variable and the exit-status rule. | `tests/platform/demo_scenarios.bats > "each demo scenario exits 0 when the platform reacts"`<br>`tests/platform/demo_scenarios.bats > "demo scenario exits non-zero when the platform does not react"`<br>`tests/docs/docs.bats > "DEMO.md documents every demo scenario"`<br>helpers `tests/supply-chain/golden.bash`, `tests/platform/dt.bash`, `tests/platform/grafana.bash`<br>fixtures, written once the catalog holds the genuine older golden entries (M9 interface): `tests/fixtures/images/demo-deprecated-base/Dockerfile`, `tests/fixtures/images/demo-eol-base/Dockerfile` |
| CAT-024 | 24 | M1, M2, M6, M8 | unit, live | create | Live: OpenBao KV holds a non-empty entry for Harbor admin, each Harbor robot, the DT API key, the DHI pull token and the Harbor and DT database credentials (existence checked with `test -n`, value never printed); every Kubernetes Secret holding one of them is owned by an ExternalSecret. Each milestone adds its credentials to the test (M1 mechanism, M2 Harbor admin + robots + DB + DHI pull token, M6 the DT database, admin password and dt-bridge API key, and the dt-bridge Secrets of its Harbor robot and DHI credentials, M8 the Grafana admin `platform/grafana-admin` → `observability/grafana-admin`). Unit: gitleaks over the full git history reports nothing; the `DHI_TOKEN` value from the environment appears in no tracked file and no commit diff (`git grep -qF` / `git log -S` with output discarded). | `tests/platform/secrets.bats > "OpenBao holds every platform credential"`<br>`tests/platform/secrets.bats > "credential Secrets are delivered only by External Secrets"`<br>`tests/ci/secrets.bats > "git history holds no secret"`<br>`tests/ci/secrets.bats > "DHI token value is not committed"`<br>`tests/platform/harbor_configure.bats > "OpenTofu state is git-ignored, encrypted by OpenBao Transit and holds no robot secret"` |
| CAT-025 | 25 (+ 22 doc, Decision 17) | M9 | unit | modify | `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT-MODEL.md`, `docs/DEMO.md`, `docs/ROADMAP.md` exist and are non-empty; `docs/adr/` holds one distinct ADR (Context, Decision, Consequences) per decision, matched by title: Kyverno CEL-only, Kubescape over Trivy Operator + Falco, Dependency-Track + dt-bridge, OpenTofu + goharbor provider over harbor-cli (no ADR titled harbor-cli over Terraform/OpenTofu), transparent mirror + trust tiers, keyless signing; an ADR records the Grype/Trivy divergence. "In English" is checked heuristically (no paragraph dominated by French function words, every required document present), a partial proof. README documents the prerequisites and the memory measurement of criterion 22 (`kubectl top nodes`, working set with page cache, 12 GiB). ROADMAP lists the Decision 17 items (air-gap bundle, Gatekeeper/Rego, Buildah, chart relocation as OCI) and keeps the upstream issues (DependencyTrack/dependency-track#6132, #6957, kyverno/sdk#125). | `tests/docs/docs.bats > "required documents exist"`<br>`tests/docs/docs.bats > "one ADR per structuring decision"`<br>`tests/docs/docs.bats > "documents are written in English"`<br>`tests/docs/docs.bats > "README documents the prerequisites and the memory budget measurement"`<br>`tests/docs/docs.bats > "roadmap lists the out-of-scope items and the tracked upstream issues"` |

No criterion is skipped. Partial proofs, reported as such at the merge gate: CAT-001 (a down
state stands in for a clean machine), CAT-005 (before the merge, "a push to `main`" is proven
statically by the trigger and live on the PRD branch; the live tests prove it on `main` only when
run after the merge), CAT-009 to CAT-012 (admission proven on an ephemeral cluster with E2E params:
GHCR fixtures instead of Harbor, fixture-only `deprecated`/`eol` catalog entries on DHI stand-in
digests, "missing" labels simulated by empty values; the live platform's admission is not asserted
at M4), CAT-013 ("every PR" over time), CAT-015 (the JVM trust store is proven by the JVM's own
properties: hello-java makes no TLS call at M5; the store's content is CAT-D04's; admission of the running pods is
proven by a dry-run of their exact spec through fail-closed webhooks, the PolicyReport `pass` results being eventual), CAT-017 (finding-level
`NOT_AFFECTED` unproven: DT lists no Debian finding until DependencyTrack/dependency-track#6132 lands; fetch,
conversion and DT acceptance are proven), CAT-018 (same limit for runtime OpenVEX: collection, conversion and DT acceptance are proven, finding-level `NOT_AFFECTED` waits for a DT finding a runtime statement covers), CAT-021 (the harbor-trivy `after` VEX count is bounded — no lower than the report entries DHI does not name, no higher than `before`, below it when DHI covers a reported CVE — not recomputed entry by entry; the Kubescape runtime VEX part of `after` for app images is not asserted; the dependency-track series are exact but all zero while DT lists no finding, DependencyTrack/dependency-track#6132), CAT-023 ("non-zero otherwise" is proven by a negative control for the seven admission scenarios only; for `runtime-shell` and `vex` it rests on the reaction being observable before the task returns — alert dated before the exit, DT token already `COMPLETED` — with no scenario where the platform fails to react), CAT-025 (English detected heuristically).

## Démo

### P1 — Voir la plateforme refuser une image non conforme
Critères : 9, 10, 11, 23
Surface : cli
Départ : plateforme démarrée (`task up` terminé), terminal à la racine du dépôt
1. Lance `task demo:unsigned` — l'admission refuse le pod : image non signée
2. Lance `task demo:foreign-signer` — refus : signature d'une autre identité que le workflow du dépôt
3. Lance `task demo:direct-dockerhub` — refus : image hors des projets Harbor `golden`/`apps`
4. Lance `task demo:non-golden-base` — refus : image construite sur une base absente du catalogue
5. Lance `task demo:eol-base` — refus : base golden en fin de vie
6. Lance `task demo:root` — refus : le pod viole Pod Security `restricted`
7. Lance `task demo:deprecated-base` — le pod est admis, l'avertissement de dépréciation s'affiche
8. Affiche l'image du pod admis — la référence a été réécrite en digest `@sha256:`

### P2 — Suivre une image du golden path jusqu'au tri des CVE
Critères : 6, 15, 16, 17
Surface : web
Départ : plateforme démarrée, `dt-bridge` et `hello-java` déployés, navigateur ouvert sur Harbor avec le compte admin seedé
1. Ouvre le projet Harbor `golden` — les images python et java sont présentes, tags immuables
2. Ouvre le projet `apps`, puis le dépôt `hello-java`
3. Ouvre l'artefact — la signature, les SBOM et la provenance apparaissent comme accessoires
4. Ouvre Dependency-Track, liste des projets — le projet `hello-java` porte le tag en version
5. Ouvre le projet — les composants viennent du SBOM attesté
6. Ouvre le projet `golden/python`, onglet audit des vulnérabilités — aucune CVE Debian n'est listée : Dependency-Track ne rapproche pas encore les paquets source Debian (DependencyTrack/dependency-track#6132), le VEX DHI accepté n'y marque donc encore aucune CVE `NOT_AFFECTED`

### P3 — Repérer un shell dans un conteneur depuis Grafana
Critères : 12, 20, 21
Surface : web
Départ : plateforme démarrée, `task demo:runtime-shell` lancé il y a moins de 2 minutes, navigateur ouvert sur Grafana avec le compte seedé
1. Ouvre le tableau de bord « image posture »
2. Sélectionne l'image golden python
3. Lit les compteurs de CVE par sévérité, avant et après VEX
4. Lit la part d'images signées et attestées en cours d'exécution
5. Repère l'alerte runtime du shell ouvert dans le pod ciblé
6. Ouvre Explore sur VictoriaLogs — l'événement Kubescape détaillé s'affiche
7. Ouvre Policy Reporter — les PolicyReports Kyverno sont listés, dont l'avertissement de base dépréciée et le registre hors liste en namespace plateforme
