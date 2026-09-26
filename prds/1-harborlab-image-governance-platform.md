# PRD #1 — harborlab: Image Governance Platform

**Issue**: [#1](https://github.com/naqa92-portfolio-projects/harborlab/issues/1) · **Priority**: High · **Status**: Draft

## Acceptance criteria

1. On a clean machine with the prerequisites met, `devbox run -- task up` creates the kind cluster and exits 0 only after every ArgoCD Application has been Synced and Healthy for 60 consecutive seconds.
2. `devbox run -- task down` deletes the cluster and the isolated kubeconfig, and a subsequent `task up` succeeds again.
3. Running `devbox run -- task harbor:configure` twice in a row produces no change on the second run: the OpenTofu plan of the second run is empty for projects, proxy caches, replication rules, robots, immutability, retention, webhooks and deployment security, and the Harbor state is unchanged.
4. Once Harbor is up, a pod pulling `docker.io`, `quay.io`, `ghcr.io`, `registry.k8s.io` or `dhi.io` images is served through the matching Harbor proxy-cache project (the artifact appears in that project); with Harbor scaled to 0, the same pull still succeeds through the upstream fallback.
5. A push to `main` touching `images/golden/**` publishes `ghcr.io/<owner>/harborlab/golden/{python,java}` images whose DHI base signature was verified during the build, and that carry a cosign keyless signature, a CycloneDX SBOM attestation, an SPDX SBOM attestation and a SLSA provenance attestation, all verifiable with `cosign verify` / `cosign verify-attestation` against the identity of this repository's workflow.
6. After replication, the same golden and app images in Harbor `golden`/`apps` still verify with cosign (signature and all attestations) against the Harbor reference.
7. An application Dockerfile only needs `FROM <golden image>` and its workflow only needs one `uses:` line pointing to the reusable `build-image.yml` to produce a signed, attested, VEX-aware Trivy-scanned image; no other security configuration is required from the app.
8. `images/catalog.yaml` is the single source of truth for golden images (name, version, digest, status `supported|deprecated|eol`, dates); the Kyverno parameters ConfigMap and the catalog documentation are generated from it and CI fails if the generated files are out of date.
9. In a namespace labelled `harborlab.io/tier=workload`, admission denies: an unsigned image, an image signed by another identity, an image not served from Harbor `golden`/`apps`, an image whose SLSA provenance base digest is absent from the catalog or marked `eol`, an image without SBOM attestation, an image missing the required OCI/`io.harborlab.*` labels, and a pod violating Pod Security Standards `restricted`.
10. In a workload namespace, an image built from a `deprecated` golden base is admitted with a visible admission warning and a PolicyReport entry.
11. Admitted workload images are rewritten to their digest by admission.
12. In platform namespaces, images from registries outside the allow-list are reported, and images of vendors that publish signatures (at least Kyverno, Cilium, ArgoCD) are verified; bootstrap namespaces (kube-system, cilium, argocd, kyverno) are explicitly excluded and the exclusion is documented in the threat model.
13. `kyverno test` unit tests and a Chainsaw E2E suite running on an ephemeral kind cluster in GitHub Actions pass on every PR touching `policies/**`, and cover each deny/warn case of criteria 9–10.
14. The platform CI fails a PR on: a GitHub Actions workflow finding from zizmor, an action not pinned by SHA, a secret detected by gitleaks, a hadolint error, a Trivy misconfiguration of severity HIGH or above, a kube-linter error, or a Dockerfile whose `FROM` is not a supported catalog golden image.
15. `dt-bridge` and `hello-java` are built through the golden path and run admitted in a workload namespace, deployed by ArgoCD.
16. When an image is pushed or replicated into Harbor `golden`/`apps`, `dt-bridge` uploads the SBOM attested at build time (not a regenerated one) to Dependency-Track, into a project named after the image with the tag as version.
17. For a DHI-based image, the DHI OpenVEX `not_affected` statements are converted to CycloneDX VEX and applied in Dependency-Track, so that the corresponding findings show analysis state `NOT_AFFECTED` with the vendor justification.
18. Kubescape runtime OpenVEX documents for running workloads are forwarded by `dt-bridge` to Dependency-Track the same way as criterion 17.
19. `dt-bridge` unit tests (pytest) cover SBOM extraction, OpenVEX → CycloneDX VEX conversion (including unknown status and malformed documents) and DT API error handling, using fixed fixtures; `ruff check` and `ruff format --check` pass.
20. `task demo:runtime-shell` (shell exec in a workload container) produces a Kubescape runtime alert that is visible in Grafana through VictoriaLogs within 2 minutes.
21. Grafana exposes an "image posture" dashboard showing, per golden image: CVE counts by severity (before/after VEX), share of signed/attested running images, admission violations and runtime alerts; Policy Reporter UI lists Kyverno PolicyReports.
22. With every component running, cluster memory usage (`kubectl top nodes`) stays at or below 10 GiB.
23. Each `task demo:<scenario>` (`unsigned`, `foreign-signer`, `non-golden-base`, `deprecated-base`, `eol-base`, `direct-dockerhub`, `root`, `runtime-shell`, `vex`) exits 0 when the platform reacts as documented in `docs/DEMO.md` and non-zero otherwise.
24. OpenBao holds every platform credential (Harbor admin and robots, Dependency-Track API key, DHI pull token, database credentials); workloads receive them only through External Secrets, and no secret value is committed to Git.
25. `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT-MODEL.md`, `docs/DEMO.md`, `docs/ROADMAP.md` and at least one ADR per structuring decision (Kyverno CEL-only, Kubescape over Trivy Operator + Falco, Dependency-Track + dt-bridge, OpenTofu + goharbor provider over harbor-cli, transparent mirror + trust tiers, keyless signing) exist, in English.

## Prerequisites

- devbox installed — check: command -v devbox
- Docker daemon running — check: docker info >/dev/null 2>&1
- GitHub CLI logged in — check: gh auth status
- Repository is public (keyless signing identity, public GHCR images, Scorecard) — check: test "$(gh repo view naqa92-portfolio-projects/harborlab --json visibility -q .visibility)" = PUBLIC
- Docker account token for dhi.io in local `.env` — check: grep -q '^DHI_TOKEN=.' .env
- Docker account token for dhi.io in GitHub Actions secrets — check: gh secret list --repo naqa92-portfolio-projects/harborlab | grep -q '^DHI_TOKEN'
- Docker account name owning the dhi.io token in local `.env` — check: grep -q '^DHI_USERNAME=.' .env
- Docker account name owning the dhi.io token in GitHub Actions secrets — check: gh secret list --repo naqa92-portfolio-projects/harborlab | grep -q '^DHI_USERNAME'
- At least 16 GiB RAM available to WSL — check: test "$(free -g | awk '/^Mem:/{print $2}')" -ge 16

## State
phase: 2
milestone: 4/10
worktree: /home/naqa/harborlab-prd-1-prd-1-harborlab-image-governance-platform
branch: prd-1-prd-1-harborlab-image-governance-platform
catalog: tests/CATALOG.md
gate: none
red_ahead: none
decision: M0 test 3 (and CAT-004) assert artifact by linux/amd64 platform digest, not tag; wait ≤240s (Harbor ManifestCache 10×20s); test image shares no layer with the node — human, 2026-09-26 (test amended aa48447, 3/3 pass on coder commits ca0d758..9927239)
notes: M1 coder e988fc6..2566a8c (spike cluster stopped); M1 — "DHI token value is not committed" and "git history holds no secret" are invariants, LOAD_BEARING=false accepted for them and reported at the gate; DHI_TOKEN reaches tasks via Taskfile dotenv of git-ignored .env, CI via the GH secret
notes-m2: human decisions — dhi.io fallback proven via ESO pull secret; DHI_USERNAME added; Decision 8 → OpenTofu; robot check via GET /v2/. M2 coder commits 9cdcded 2bd927c 3f1882e 3fb4857 24f44d8 ec3cb3e f69272f (OpenTofu); gate notes: robot secret_wo_version manual bump on rotation, deprecated vault data source for dhi access_secret
notes-m3: red 065c9756; CAT-003 amended — Harbor github-ghcr adapter cannot list GHCR (only specific repository names), replication filters become explicit {python,java} / {dt-bridge,hello-java}; accepted by orchestrator (adapter contract, not a workaround), golden filter to derive from images/catalog.yaml
resolved-m3: human (2026-09-26) — harbor_replicated loop must treat Succeed/Success as success (Harbor replication API vocabulary); Decision 4 → internal CA via trust-manager at runtime; red rework 45e429d (trust_bundle, golden_dockerfiles, replication loop fixed); coder next: trust-manager — done dac344c 159db69; gate note: Argo CD v3.5.3 panics (counter cannot decrease) when the WSL2 clock steps back, can block task up
notes-m4: red 2c89462; deprecated-base expected result fail on a [Warn, Audit] policy (CEL policies never report warn) — accepted, criterion 10 proven by Chainsaw warning + PolicyReport
notes-m4b: coder M4 up to c39142e — kyverno CLI deadlocks with ≥2 image-verifying policies per resource (kyverno/sdk#125, fix PR #127 open & unreviewed, no release). Orchestrator decision: one kyverno test suite per policy (kyverno/policies repo convention), no patched CLI; run.sh must retry registry rate limits (public.ecr.aws TOOMANYREQUESTS seen in CI). M5 note: live Kyverno must trust the local CA to verify Harbor references
pr: none
findings:
- T1 pending — goharbor provider does not detect drift on harbor_replication filters/description changed out of band (plan empty after manual change; needed -replace) — raised by tester at M3 green
- T2 pending — workload signature identity accepts build-image.yml@refs/heads/(main|prd-.+): any prd-* branch can sign admissible images; production should trust main only (review at phase 3)
demo:

## Milestones

- [x] M0 — Spike: on a minimal kind cluster, a keyless-signed and attested GHCR image replicated into Harbor still verifies with cosign and is admitted by a Kyverno ImageValidatingPolicy on its Harbor reference; a containerd mirror to a Harbor proxy cache with upstream fallback is proven; findings recorded in an ADR, attestation format adjusted if needed (indépendant)
- [x] M1 — Foundation: devbox, Taskfile, local CA, kind with containerd mirrors, Cilium + Gateway API, cert-manager, ArgoCD app-of-apps, OpenBao + ESO, CNPG; `task up`/`task down` converge (dépend de M0)
- [x] M2 — Registry: Harbor on CNPG deployed by ArgoCD, `task harbor:configure` idempotent (proxy caches, `golden`/`apps` replication from GHCR, robots in OpenBao, immutability, retention, deployment security, webhooks) (dépend de M1)
- [x] M3 — Image factory: `images/catalog.yaml` + generators, golden Python/Java on DHI, reusable `build-image.yml` (SBOM CDX+SPDX, SLSA, keyless cosign, Trivy `--vex oci`), platform CI hygiene and lint, Renovate (dépend de M2)
- [ ] M4 — Admission: Kyverno CEL policies per trust tier fed by the catalog, PSA restricted, digest mutation, `kyverno test` + Chainsaw E2E in GitHub Actions (dépend de M3)
- [ ] M5 — Golden-path apps: `dt-bridge` skeleton and `hello-java` built through the reusable workflow and deployed by ArgoCD in a workload namespace (dépend de M4)
- [ ] M6 — Vulnerability management: Dependency-Track 5.1 on CNPG, Harbor webhook → `dt-bridge` → DT SBOM upload, DHI OpenVEX → CycloneDX VEX conversion, pytest coverage (dépend de M5)
- [ ] M7 — Runtime: Kubescape operator (scan, CIS, runtime threat detection, VEX generation) with runtime OpenVEX forwarded to DT (dépend de M6)
- [ ] M8 — Observability: VictoriaMetrics, VictoriaLogs, Grafana image-posture dashboard, Policy Reporter UI, memory budget verified (dépend de M7)
- [ ] M9 — Docs & demo: README, ARCHITECTURE, ADRs, THREAT-MODEL, DEMO runbook, ROADMAP (air-gap bundle, Gatekeeper/Rego comparison, Buildah builds, chart relocation as OCI), all `task demo:*` scenarios green (dépend de M8)

## Context

Portfolio project targeting roles such as "container image governance / DevSecOps expert" in regulated banking (Harbor, Trivy, Cosign, SBOM SPDX/CycloneDX, Kyverno/Gatekeeper, ArgoCD, naming/versioning/labels/lifecycle governance, compliance as code). It is the K8s-native answer to Repod (self-hosted APT/RPM/APK gatekeeper): delegate OS packages to a vendor that proves its work (Docker Hardened Images), then govern OCI artifacts end to end.

Security is **shifted down** to the platform rather than left to developers: the application contract is `FROM <golden>` plus one reusable-workflow line; the platform owns build, attestation, registry, admission, runtime detection and triage.

## Architecture

```
dhi.io ──(verify DHI sig)──► GHA golden.yml ──► ghcr.io/…/golden/{python,java}   (signed + SBOM + SLSA)
app dir ──► GHA build-image.yml (reusable, platform-owned) ──► ghcr.io/…/apps/*   (signed + SBOM + SLSA + VEX-aware Trivy)
ghcr.io ──(Harbor pull replication)──► harbor/{golden,apps} ──webhook──► dt-bridge ──► Dependency-Track
ArgoCD ──► Kyverno admission (our workflow identity, catalog-approved base, SBOM, labels, registry) ──► pods
Kubescape (scan, CIS, runtime alerts, runtime OpenVEX) ──► dt-bridge ──► DT   |   Policy Reporter · Grafana · VictoriaLogs
```

## Decisions

| # | Topic | Decision |
|---|---|---|
| 1 | Narrative | Image factory / governance platform; apps are only consumers |
| 2 | Repo | Public monorepo `harborlab`, English; labels `io.harborlab.*` |
| 3 | Build | GitHub Actions → GHCR, keyless cosign (GitHub OIDC), SBOM CycloneDX + SPDX, SLSA provenance; Harbor pull-replicates GHCR (DMZ → internal) |
| 4 | Golden images | DHI upstream, DHI signature verified at ingestion, thin golden layer (governance labels, non-root user) re-signed; internal CA delivered at runtime by cert-manager trust-manager (`Bundle` → PEM + PKCS#12 ConfigMap per namespace), not baked into images; Python + Java (Temurin JRE); Renovate pins digests |
| 5 | Apps | `dt-bridge` (Python/FastAPI, uv) dogfooded through the golden path; `hello-java` (Spring Boot); non-compliant fixtures for demos |
| 6 | Admission | Kyverno ≥ 1.19, CEL policy types only (ClusterPolicy deprecated, removed in 1.20); native PSA `restricted` |
| 7 | Governance | `images/catalog.yaml` source of truth → Kyverno params + docs; SLSA provenance must prove a supported golden base (deprecated = warn, EOL/unknown = deny); Harbor immutable tags + retention |
| 8 | Harbor config | Helm via ArgoCD; configuration declared with OpenTofu and the official `goharbor/harbor` provider (devbox), run by `task harbor:configure`; robot secrets generated in OpenBao and passed write-only (`secret_wo`, never in state); local state encrypted with the OpenBao Transit key provider. harbor-cli rejected (pre-1.0: no piped `--password-stdin`, prints robot secrets, no scheduled retention / non-interactive immutability / replication namespace flattening); Crossplane Harbor providers rejected (stale or single-maintainer) |
| 9 | Trust model | Transparent containerd mirrors → Harbor proxy caches with upstream fallback (no SPOF, bootstrap-safe); tiers: workloads = full chain, platform = registry allow-list + vendor signatures when published, bootstrap = documented exception |
| 10 | Cluster | kind single node, Cilium (kube-proxy replacement, Gateway API on host network), local CA trusted by containerd and used by cert-manager, `*.127.0.0.1.nip.io` |
| 11 | Secrets | OpenBao (Kubernetes auth, least-privilege policies) + External Secrets; seeded from git-ignored `.env` |
| 12 | Databases | CloudNativePG, one single-instance cluster each for Harbor and Dependency-Track |
| 13 | In-cluster scan & runtime | Kubescape 4 operator replaces Trivy Operator and Falco (Grype scan, CIS/NSA, runtime threat detection, reachability OpenVEX — experimental) |
| 14 | Triage | Dependency-Track 5.1 + `dt-bridge`; OpenVEX → CycloneDX VEX conversion isolated in one module, removable once DT supports OpenVEX import (DependencyTrack/dependency-track#7094) |
| 15 | Observability | VictoriaMetrics single + VictoriaLogs + Grafana + Policy Reporter UI |
| 16 | Platform CI | zizmor, SHA pinning, gitleaks, OpenSSF Scorecard, Renovate, hadolint, Trivy config, kube-linter, FROM-golden rule, `kyverno test`, Chainsaw on ephemeral kind |
| 17 | Out of scope | Air-gap bundle, Gatekeeper/Rego, Buildah builds, chart relocation as OCI → `docs/ROADMAP.md` |

## Risks

| Risk | Mitigation |
|---|---|
| Signatures/attestations (cosign classic vs Sigstore bundle / OCI referrers) not preserved by GHCR → Harbor replication, or not readable by Kyverno | M0 spike before any other work; ADR records the chosen format |
| Kyverno CEL cannot read image config labels | Validate in M4; fallback: CI check + attested label set |
| Kubescape VEX generation is experimental (~2 min observation, `docker.io` vs `index.docker.io` naming) | Normalise references in `dt-bridge`; document limits |
| Provider credentials without a write-only variant (registry `access_secret`) land in OpenTofu state | State encrypted with the OpenBao Transit key provider, state file git-ignored; covered by criterion 24 |
| Grype (in-cluster) and Trivy (CI/Harbor) CVE results diverge | Documented in an ADR; DT is the triage source of truth |
| Keyless signing uses the public Rekor log, unlike a bank KMS/HSM setup | Documented in the threat model with the KMS alternative |
| Memory pressure on a 23 GiB WSL host | Budget checked in M8 (criterion 22) |
