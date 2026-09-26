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
  robots, the Harbor DB and the DHI pull token, M6 the DT API key and DB.
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
  | `secret/platform/harbor-robot-dt-bridge` | `username` (= `robot$dt-bridge`), `password` | none until dt-bridge (M6) — `-\|-` in `PLATFORM_CREDENTIALS` |
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
  entry unchanged plus fixture-only entries that never enter `images/catalog.yaml`:
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
  resolves to the pod's loopback). The PolicyReport of each app pod (`scope` = the pod) holds, within 150 s,
  a `pass` from `workload-image-signature`, `workload-golden-base`, `workload-golden-base-deprecated`,
  `workload-image-labels` and `workload-registry`, and no other result from a `workload-*` policy. At test
  time, a server-side dry-run of a restricted pod `admission-probe` on
  `harbor.127.0.0.1.nip.io/apps/<app>@<digest>` in the app namespace is admitted without `Warning`, and the
  same pod on `ghcr.io/naqa92-portfolio-projects/harborlab/apps/<app>@<digest>` is denied naming
  `workload-registry` (control: the policies enforce there).
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
| CAT-008 | 8 | M3 | unit | create | `task catalog:validate` accepts `tests/fixtures/catalog/valid.yaml` (control) and rejects, naming the field, `missing-digest.yaml`, `invalid-status.yaml` (status outside `supported\|deprecated\|eol`), `malformed-digest.yaml` and `invalid-date.yaml` (2027-02-30); `images/catalog.yaml` validates and holds a supported python and java entry; `task catalog:generate` in a temp copy of the working tree reproduces the committed Kyverno params ConfigMap `policies/params/golden-images.yaml` and doc `docs/golden-images.md` byte for byte, the ConfigMap maps every entry `sha256.<hex>` to its status and the doc has a row per entry; in a temp copy, `task catalog:check` passes (control), then fails after an entry's status is changed without regenerating, leaves the ConfigMap untouched, and passes again after `catalog:generate`, whose ConfigMap carries the new status; the platform CI workflow runs `task catalog:check` in a blocking step on every `pull_request`. | `tests/ci/catalog.bats > "catalog validation rejects invalid entries"`<br>`tests/ci/catalog.bats > "generated ConfigMap and doc match the catalog"`<br>`tests/ci/catalog.bats > "drift check fails when generated files are out of date"`<br>`tests/ci/catalog.bats > "platform CI runs the catalog drift check on pull requests"`<br>fixtures `tests/fixtures/catalog/{valid,missing-digest,invalid-status,malformed-digest,invalid-date}.yaml` |
| CAT-009 | 9 | M4 | unit, e2e | create | `kyverno test` through `tests/kyverno/run.sh` (with `--registry`, against real fixture images published by the repo's fixtures workflow, tags pinned and image metadata fetched from the registry at run time, E2E params in the context): `fail` of the rule's own policy for unsigned and foreign signer (`workload-image-signature`), non-Harbor registry (`workload-registry`, compliant image outside the allow-list), EOL base and base digest absent from the catalog (`workload-golden-base`), no SBOM attestation (`workload-image-signature`), missing OCI/`io.harborlab.*` labels (`workload-image-labels`), each case also passing the policies it satisfies; `pass` of every workload policy for the compliant golden-path image; the MutatingPolicy `workload-pod-security` labels a workload Namespace Pod Security `restricted`. Chainsaw on an ephemeral kind cluster: each of those pods, plus a pod running as root, is rejected in a `harborlab.io/tier=workload` namespace with the policy name and message of the M4 interface (Pod Security: `violates PodSecurity "restricted:latest"`, after the platform labelled the namespace), and the compliant pod is admitted without warning with a `pass` from every workload policy in its PolicyReport. PSS `restricted` is native PSA, which `kyverno test` does not evaluate: it is proven by Chainsaw only. | `tests/kyverno/workload/image-signature/kyverno-test.yaml > unsigned, foreign-signer, no-sbom (fail); compliant and the others (pass)`<br>`tests/kyverno/workload/registry/kyverno-test.yaml > non-harbor-registry (fail); compliant and the others (pass)`<br>`tests/kyverno/workload/golden-base/kyverno-test.yaml > eol-base, unknown-base (fail); compliant, deprecated-base and the others (pass)`<br>`tests/kyverno/workload/image-labels/kyverno-test.yaml > missing-labels (fail); compliant and the others (pass)`<br>`tests/kyverno/workload/pod-security/kyverno-test.yaml > new-workload namespace (patched)`<br>harness `tests/kyverno/run.sh`<br>`tests/chainsaw/workload/unsigned/chainsaw-test.yaml`<br>`tests/chainsaw/workload/foreign-signer/chainsaw-test.yaml`<br>`tests/chainsaw/workload/non-harbor-registry/chainsaw-test.yaml`<br>`tests/chainsaw/workload/eol-base/chainsaw-test.yaml`<br>`tests/chainsaw/workload/unknown-base/chainsaw-test.yaml`<br>`tests/chainsaw/workload/no-sbom/chainsaw-test.yaml`<br>`tests/chainsaw/workload/missing-labels/chainsaw-test.yaml`<br>`tests/chainsaw/workload/pss-restricted/chainsaw-test.yaml`<br>`tests/chainsaw/workload/compliant/chainsaw-test.yaml`<br>fixtures (shared by the workload suites) `tests/kyverno/workload/{values,context}.yaml`, `tests/kyverno/workload/resources/{pods,namespace}.yaml`, `tests/kyverno/workload/patched/namespace.yaml`, `tests/chainsaw/workload/*/pod.yaml`, `tests/chainsaw/params/{golden-images,registries}.yaml`, `tests/fixtures/images/{compliant,missing-labels,deprecated-base,eol-base,unknown-base}/Dockerfile` |
| CAT-010 | 10 | M4 | unit, e2e | create | `kyverno test`: a pod built on a base the E2E catalog marks `deprecated` fails `workload-golden-base-deprecated` (Kyverno CEL policies report `fail`, never `warn`; that policy's actions are `[Warn, Audit]`, checked by CAT-013) and passes `workload-golden-base` and the other workload policies. Chainsaw: in a workload namespace the pod is admitted, `kubectl apply` stderr carries a `Warning:` naming `workload-golden-base-deprecated` with its deprecation message, and the pod's PolicyReport holds that policy's `fail` result next to a `pass` from `workload-golden-base`. | `tests/kyverno/workload/golden-base-deprecated/kyverno-test.yaml > deprecated-base (fail); compliant and the others (pass)`<br>`tests/kyverno/workload/{golden-base,image-signature,image-labels,registry}/kyverno-test.yaml > deprecated-base (pass)`<br>`tests/chainsaw/workload/deprecated-base/chainsaw-test.yaml` (+ `pod.yaml`) |
| CAT-011 | 11 | M4 | e2e | create | Chainsaw: a compliant pod referencing `…/fixtures/compliant:e2e` is admitted and its stored `spec.containers[0].image` ends with `@sha256:<digest the tag serves>` (read with `crane digest` at test time). | `tests/chainsaw/workload/digest-mutation/chainsaw-test.yaml` (+ `pod.yaml`) |
| CAT-012 | 12 | M4 | unit, e2e | create | `kyverno test`: in a platform namespace a pod from a registry outside the allow-list (`public.ecr.aws`) fails `platform-registry-allow-list` (Audit), allow-listed ones pass; the Kyverno, Cilium and Argo CD images pass `platform-vendor-signatures`, and an Argo CD release published before Argo CD signed its images (`v2.4.0`) fails it (negative control). Chainsaw: in a platform-tier namespace the off-list pod is admitted and its PolicyReport holds a `fail` result, the allow-listed one a `pass`; pods running the Kyverno, Cilium and Argo CD vendor images get a `pass` from the vendor-signature policy and the unsigned Argo CD release a `fail`; with `kube-system`, `cilium`, `argocd` and `kyverno` labelled platform, an off-list pod in each produces no PolicyReport while the same pod in a platform namespace (control) is reported. Docs: `docs/THREAT-MODEL.md` names the four bootstrap namespaces as an explicit exclusion. | `tests/kyverno/platform/registry-allow-list/kyverno-test.yaml > off-list-registry (fail); allow-listed-registry, vendor images (pass)`<br>`tests/kyverno/platform/vendor-signatures/kyverno-test.yaml > vendor-kyverno, vendor-cilium, vendor-argocd (pass); vendor-unsigned (fail)`<br>`tests/chainsaw/platform/off-list-registry/chainsaw-test.yaml`<br>`tests/chainsaw/platform/vendor-signatures/chainsaw-test.yaml`<br>`tests/chainsaw/platform/bootstrap-excluded/chainsaw-test.yaml`<br>`tests/docs/docs.bats > "threat model documents the bootstrap namespace exclusion"`<br>fixtures (shared by the platform suites) `tests/kyverno/platform/{values,context}.yaml`, `tests/kyverno/platform/resources/pods.yaml`, `tests/chainsaw/platform/off-list-registry/pods.yaml`, `tests/chainsaw/platform/vendor-signatures/pods.yaml`, `tests/chainsaw/platform/bootstrap-excluded/{namespaces,pods,control}.yaml` |
| CAT-013 | 13 | M4 | unit | create | The policy workflow triggers on `pull_request` (no branch filter) with `paths` absent or covering `policies/**`; blocking jobs run `tests/kyverno/run.sh` (`kyverno test --registry` on `tests/kyverno`) and, on a kind cluster created in the job with Kyverno installed by Helm and `policies/workload`, `policies/platform` and the E2E params applied, `chainsaw test` on `tests/chainsaw`; the `kyverno` CLI (≥ 1.19) and `chainsaw` are on the Devbox PATH. Each deny/warn case of criteria 9–10 (8 deny + 1 warn) has a Chainsaw case directory, and each except PSS `restricted` a `kyverno test` `fail` of its policy in that policy's own suite; every suite under `tests/kyverno` loads exactly one policy and each M4 policy has exactly one suite; the policies are the M4 interface's CEL types, names and actions (deny policies `Deny`, the deprecation policy `Warn` + `Audit` without `Deny`, platform policies `Audit` without `Deny`), and nothing under `policies/` is a `ClusterPolicy`/`Policy`. The E2E params keep every production entry unchanged and only add fixture entries (`deprecated`/`eol` digests absent from `images/catalog.yaml`, the GHCR fixtures prefix); the production workload allow-list is exactly Harbor `golden`/`apps`; the `kyverno test` contexts equal the E2E params and mock no image, and every suite reads its tier's context; each fixture base has the status its case stands for. "Every PR" over time is not observable; the trigger wiring and the passing suites (CAT-009/010) are. | `tests/ci/policy_ci.bats > "policy workflow runs kyverno test and Chainsaw on PRs touching policies"`<br>`tests/ci/policy_ci.bats > "every deny and warn case of criteria 9-10 has a kyverno test and a Chainsaw case"`<br>`tests/ci/policy_ci.bats > "E2E params extend the production params with fixture-only entries"` |
| CAT-014 | 14 | M3 | unit | create | `task lint -- <dir>` (the task the platform CI runs) on fixture git repositories generated in `$BATS_TEST_TMPDIR`: a clean baseline passes with no `FAILED` line (control); each fixture adds one defect and the lint exits non-zero with `FAILED <check>` for that check: zizmor (template injection of the PR title in `run:`), `pinned-actions` (`actions/checkout@v7.0.1`), gitleaks (fake GitHub token committed), hadolint (DL3000 relative `WORKDIR`), `trivy-config` (privileged Pod, HIGH), kube-linter (Deployment selector matching none of its pods), `from-golden` (`FROM docker.io/library/python`, and `FROM` a golden digest marked `eol` in the fixture catalog); `task lint` exits 0 on the repository itself; the platform CI runs `task lint` in a blocking step of a `fetch-depth: 0` job on every `pull_request`. The criterion does not say whether a `deprecated` base passes this rule: not asserted. | `tests/ci/platform_lint.bats > "platform lint passes on a clean fixture"`<br>`tests/ci/platform_lint.bats > "zizmor finding fails the lint"`<br>`tests/ci/platform_lint.bats > "action not pinned by SHA fails the lint"`<br>`tests/ci/platform_lint.bats > "detected secret fails the lint"`<br>`tests/ci/platform_lint.bats > "hadolint error fails the lint"`<br>`tests/ci/platform_lint.bats > "Trivy HIGH misconfiguration fails the lint"`<br>`tests/ci/platform_lint.bats > "kube-linter error fails the lint"`<br>`tests/ci/platform_lint.bats > "FROM outside supported golden images fails the lint"`<br>`tests/ci/platform_lint.bats > "platform lint passes on the repository"`<br>`tests/ci/platform_lint.bats > "platform CI runs the lint on pull requests"` |
| CAT-015 | 15 | M5 | live | create | For each app: Argo CD Application `<app>` is Synced and Healthy and manages Deployment `<app>` in namespace `<app>`, labelled `harborlab.io/tier=workload` and enforcing Pod Security `restricted`; the Deployment is fully available and its pods Running and Ready; every pod image is a Harbor `golden`/`apps` digest reference and the app container runs `harbor.127.0.0.1.nip.io/apps/<app>@sha256:…`, whose digest verifies with cosign against the `build-image.yml` admission identity with a SLSA provenance naming exactly one base, a `supported` catalog golden image. Live admission: each pod's PolicyReport holds a `pass` from the five workload policies and nothing else from them; a server dry-run of a restricted pod on the Harbor digest is admitted without warning while the same digest from GHCR is denied by `workload-registry` (control). The app answers through its Service on port 8080 (dt-bridge `GET /healthz` → `{"status": "ok"}`, hello-java `GET /` → 200). Decision 4 at runtime: the container mounts ConfigMap `harborlab-trust` at `/etc/harborlab-trust`; Python's default TLS context in dt-bridge (`SSL_CERT_FILE`) holds the local CA; the JVM of hello-java uses `/etc/harborlab-trust/truststore.p12` as a PKCS12 trust store (`JAVA_TOOL_OPTIONS`). | `tests/platform/golden_path_apps.bats > "dt-bridge runs admitted in a workload namespace, deployed by ArgoCD"`<br>`tests/platform/golden_path_apps.bats > "hello-java runs admitted in a workload namespace, deployed by ArgoCD"` |
| CAT-016 | 16 | M6 | live | create | A Harbor replication run for `apps/hello-java` (triggered through the Harbor API) leads, within 5 min, to a Dependency-Track project named after the image with the tag as version; the component purls of the SBOM stored in DT equal those of the CycloneDX attestation fetched with `cosign verify-attestation --type cyclonedx` (the attested SBOM, not a regenerated one). Same check for `golden/python`. DT API key read from its cluster Secret, never printed. | `tests/platform/dt_sbom_upload.bats > "replicated app image SBOM lands in Dependency-Track as attested"`<br>`tests/platform/dt_sbom_upload.bats > "replicated golden image SBOM lands in Dependency-Track as attested"` |
| CAT-017 | 17 | M6 | live | create | For the DT project of a DHI-based image, every CVE marked `not_affected` in the DHI OpenVEX document of its base (fetched from dhi.io with `DHI_TOKEN` from the environment via `--password-stdin`) that DT lists as a finding has analysis state `NOT_AFFECTED` and the vendor justification; the test fails if no such finding exists (non-vacuous). Conversion logic itself is covered by CAT-019. | `tests/platform/dt_vex.bats > "DHI not_affected statements show as NOT_AFFECTED with vendor justification"` |
| CAT-018 | 18 | M7 | unit, live | create | Live: Kubescape has produced a runtime OpenVEX document for the running `dt-bridge` workload; for each of its `not_affected` statements whose CVE is a DT finding of that project, DT shows `NOT_AFFECTED` with the justification; at least one such statement exists. Unit: `docker.io/...` and `index.docker.io/...` references from Kubescape normalise to the same DT project. | `tests/platform/runtime_vex.bats > "Kubescape runtime OpenVEX is applied in Dependency-Track"`<br>`apps/dt-bridge/tests/test_vex.py::test_kubescape_image_reference_is_normalised` |
| CAT-019 | 19 | M6 | unit | create | pytest with fixed fixtures (real-shaped CycloneDX attestation envelope, DHI-style OpenVEX sample, fake DT API key): SBOM extracted unchanged from the DSSE/in-toto envelope and a non-CycloneDX predicate rejected; OpenVEX `not_affected` → CycloneDX VEX `not_affected` with justification mapped, unknown status and malformed documents rejected with a typed error; DT client raises typed errors on 401, 5xx and timeout (`httpx.MockTransport` at the transport boundary). `ruff check` and `ruff format --check` pass on `apps/dt-bridge`. | `apps/dt-bridge/tests/test_sbom.py::test_extracts_cyclonedx_predicate_from_attestation`<br>`apps/dt-bridge/tests/test_sbom.py::test_rejects_non_cyclonedx_predicate`<br>`apps/dt-bridge/tests/test_vex.py::test_not_affected_becomes_cyclonedx_not_affected`<br>`apps/dt-bridge/tests/test_vex.py::test_vendor_justification_is_mapped`<br>`apps/dt-bridge/tests/test_vex.py::test_unknown_status_is_rejected`<br>`apps/dt-bridge/tests/test_vex.py::test_malformed_document_is_rejected`<br>`apps/dt-bridge/tests/test_dt_client.py::test_upload_raises_on_unauthorized`<br>`apps/dt-bridge/tests/test_dt_client.py::test_upload_raises_on_server_error`<br>`apps/dt-bridge/tests/test_dt_client.py::test_upload_raises_on_timeout`<br>`tests/ci/python_lint.bats > "ruff check and format pass on dt-bridge"` |
| CAT-020 | 20 | M8 | live | create | `task demo:runtime-shell` is run; the Grafana query API (`/api/ds/query` on the VictoriaLogs datasource) returns a Kubescape runtime alert naming the target pod within 120 s of the task's start. Grafana credentials read from the cluster Secret, never printed. | `tests/platform/runtime_alert.bats > "runtime shell alert is visible in Grafana through VictoriaLogs within 2 minutes"` |
| CAT-021 | 21 | M8 | live | create | Grafana dashboard `image-posture` exists with a per-golden-image variable listing every catalog image and panels for CVE counts by severity before and after VEX, share of signed/attested running images, admission violations and runtime alerts; each panel query returns non-empty data through `/api/ds/query`; the Policy Reporter UI API lists at least one PolicyReport whose source is Kyverno. | `tests/platform/observability.bats > "image posture dashboard shows every metric per golden image"`<br>`tests/platform/observability.bats > "Policy Reporter UI lists Kyverno PolicyReports"` |
| CAT-022 | 22 | M8 | live | create | With every Application Synced and Healthy, the memory reported by `kubectl top nodes` is at most 10240 Mi. | `tests/platform/memory_budget.bats > "cluster memory stays within 10 GiB"` |
| CAT-023 | 23 | M9 | unit, live | create | Live: each of `task demo:unsigned`, `foreign-signer`, `non-golden-base`, `deprecated-base`, `eol-base`, `direct-dockerhub`, `root`, `runtime-shell`, `vex` exits 0 on the running platform. Negative control for `unsigned` and `root`: run against a namespace without `harborlab.io/tier=workload` (platform does not react), the task exits non-zero — requires the scenario tasks to take the target namespace as a variable. Unit: `docs/DEMO.md` documents each of the nine scenarios. | `tests/platform/demo_scenarios.bats > "each demo scenario exits 0 when the platform reacts"`<br>`tests/platform/demo_scenarios.bats > "demo scenario exits non-zero when the platform does not react"`<br>`tests/docs/docs.bats > "DEMO.md documents every demo scenario"` |
| CAT-024 | 24 | M1, M2, M6 | unit, live | create | Live: OpenBao KV holds a non-empty entry for Harbor admin, each Harbor robot, the DT API key, the DHI pull token and the Harbor and DT database credentials (existence checked with `test -n`, value never printed); every Kubernetes Secret holding one of them is owned by an ExternalSecret. Each milestone adds its credentials to the test (M1 mechanism, M2 Harbor admin + robots + DB + DHI pull token, M6 DT). Unit: gitleaks over the full git history reports nothing; the `DHI_TOKEN` value from the environment appears in no tracked file and no commit diff (`git grep -qF` / `git log -S` with output discarded). | `tests/platform/secrets.bats > "OpenBao holds every platform credential"`<br>`tests/platform/secrets.bats > "credential Secrets are delivered only by External Secrets"`<br>`tests/ci/secrets.bats > "git history holds no secret"`<br>`tests/ci/secrets.bats > "DHI token value is not committed"`<br>`tests/platform/harbor_configure.bats > "OpenTofu state is git-ignored, encrypted by OpenBao Transit and holds no robot secret"` |
| CAT-025 | 25 | M9 | unit | create | `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT-MODEL.md`, `docs/DEMO.md`, `docs/ROADMAP.md` exist and are non-empty; `docs/adr/` holds one ADR per decision, matched by title: Kyverno CEL-only, Kubescape over Trivy Operator + Falco, Dependency-Track + dt-bridge, OpenTofu + goharbor provider over harbor-cli, transparent mirror + trust tiers, keyless signing. "In English" is checked heuristically (no paragraph dominated by French stop words), a partial proof. | `tests/docs/docs.bats > "required documents exist"`<br>`tests/docs/docs.bats > "one ADR per structuring decision"`<br>`tests/docs/docs.bats > "documents are written in English"` |

No criterion is skipped. Partial proofs, reported as such at the merge gate: CAT-001 (a down
state stands in for a clean machine), CAT-005 (before the merge, "a push to `main`" is proven
statically by the trigger and live on the PRD branch; the live tests prove it on `main` only when
run after the merge), CAT-009 to CAT-012 (admission proven on an ephemeral cluster with E2E params:
GHCR fixtures instead of Harbor, fixture-only `deprecated`/`eol` catalog entries on DHI stand-in
digests, "missing" labels simulated by empty values; the live platform's admission is not asserted
at M4), CAT-013 ("every PR" over time), CAT-015 (the JVM trust store is proven by the JVM's own
properties: hello-java makes no TLS call at M5; the store's content is CAT-D04's), CAT-025 (English
detected heuristically).

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
6. Ouvre l'audit des vulnérabilités — les CVE couvertes par le VEX DHI sont marquées `NOT_AFFECTED`
7. Ouvre une de ces CVE — l'état d'analyse et la justification du fournisseur sont visibles

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
