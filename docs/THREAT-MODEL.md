# Threat model

harborlab governs which container images may run on the cluster. This document states what admission
trusts, per namespace tier, and the exceptions that trust relies on.

## Assets and threats

| Asset | Threat | Control |
|---|---|---|
| Workload images | Unsigned, tampered or foreign-built image deployed | Kyverno `workload-image-signature`: keyless signature and CycloneDX, SPDX and SLSA v1 attestations signed by the `build-image.yml` workflow identity |
| Golden bases | Image built on an unknown or end-of-life base | Kyverno `workload-golden-base`: the base digest recorded in the verified SLSA provenance must be `supported` or `deprecated` in `images/catalog.yaml` (deprecated warns) |
| Registry path | Image pulled from outside the governed Harbor projects | Kyverno `workload-registry`: only `harbor.127.0.0.1.nip.io/golden/` and `/apps/` |
| Traceability | Image without source, revision or owner | Kyverno `workload-image-labels`: required OCI and `io.harborlab.*` labels |
| Node | Privileged or root container | Native Pod Security Admission, `restricted` enforced on every workload namespace by `workload-pod-security` |
| Tag drift | A tag re-pointed after admission | Admission rewrites every admitted workload image to its digest (`mutateDigest`) |

## Trust tiers

| Tier | Namespaces | Admission |
|---|---|---|
| Workload | labelled `harborlab.io/tier=workload` | Full chain, enforced (`Deny`): signature and attestations by the build identity, catalog-approved base, labels, Harbor `golden`/`apps` only, Pod Security `restricted`, digest pinning |
| Platform | labelled `harborlab.io/tier=platform` | Reported only (`Audit`): registry host in the platform allow-list; Kyverno, Cilium and Argo CD images verified against their vendor's keyless GitHub Actions identity |
| Bootstrap | `kube-system`, `cilium`, `argocd`, `kyverno` | None: excluded by name (see below) |

The allow-lists live in the ConfigMap `kyverno/harborlab-registries` (`policies/params/registries.yaml`)
and the golden catalog in `kyverno/golden-images`, generated from `images/catalog.yaml`.

## Bootstrap namespaces: explicit exclusion

The namespaces `kube-system`, `cilium`, `argocd` and `kyverno` are excluded from every admission policy,
by name, even when they carry a tier label. They run the components admission itself depends on: the
API server add-ons and CoreDNS (`kube-system`), the CNI (`cilium`), the GitOps controller that deploys
the policies (`argocd`) and the policy engine (`kyverno`). Enforcing policies on them creates a
dependency loop: a Kyverno outage, a Rekor or registry outage, or a policy mistake would block the pods
needed to recover, and a cluster restart could never converge.

The exclusion is a documented, accepted risk:

- An attacker able to create pods in these namespaces bypasses admission. Access to them is limited to
  cluster administrators and the controllers installed there; no workload runs in them.
- Their images come from Helm charts and bootstrap values versioned and reviewed in Git, not from
  runtime choices.

## Keyless signing on public Rekor

Images are signed keyless: GitHub Actions obtains a short-lived Fulcio certificate bound to the workflow
identity (`build-image.yml` on this repository's `main` or `prd-*` branches), and every signature is
recorded in the public Rekor transparency log. There is no long-lived private key to steal or rotate,
and the log makes every signing event auditable.

Trade-offs for a regulated environment such as a bank:

- Signing depends on the public Sigstore infrastructure (Fulcio, Rekor, TUF root) being reachable from CI
  and from admission.
- The transparency log publishes the signing identity, the repository and the image digest: acceptable
  for this public repository, not for confidential build metadata.
- Trust is anchored in the GitHub OIDC issuer and the repository's branch protections: whoever can push
  to a trusted branch can produce admissible images. Admission currently trusts `prd-*` branches too;
  production should trust `main` only.

The alternative for a bank is key-based signing with keys held in a KMS or HSM (cosign supports AWS KMS,
GCP KMS, Azure Key Vault and HashiCorp Vault / OpenBao Transit through `--key <kms-uri>`), optionally with
a private Sigstore deployment (Fulcio and Rekor operated in-house). Admission then verifies against the
public key or the private trusted root instead of the public-good instance; the policies only change
their attestor definition.

## Known findings

Accepted or pending risks found while building the platform, with the control that would close them.

| Finding | Risk | Mitigation |
|---|---|---|
| Keyless signing on the public Rekor instead of a KMS | Signing and admission depend on public Sigstore services; signing metadata is public | Documented above; a bank signs with a KMS/HSM key (`cosign --key <kms-uri>`) or a private Sigstore, and only the policies' attestor changes |
| The workload signing identity accepts `prd-*` branches | `build-image.yml@refs/heads/(main\|prd-.+)`: any `prd-*` branch of this repository can sign admissible images, so pre-merge code reaches production admission | Production trusts `refs/heads/main` only; `prd-*` stays a development convenience |
| Branch protection is a human setting | With the identity above, the chain of trust is only as strong as who can push to `main` or create `prd-*` branches; no ruleset is declared in this repository | A repository administrator adds a ruleset protecting `main` (reviews, status checks) and restricting the creation of `prd-*` branches |
| `dt-bridge` trusts Harbor referrers for the SBOM it uploads | The CycloneDX attestation and SLSA provenance read from Harbor feed Dependency-Track and the DHI VEX lookup; a tampered referrer would mislead triage (not admission, which verifies signatures itself) | Verify the Sigstore bundles in `dt-bridge` against the build identity before use |
| The local CA has no `keyUsage` extension | Strict X.509 clients reject it; `dt-bridge` relaxes Python's strict verification for Harbor | Emit a compliant CA certificate in `task up` and drop the relaxation |
| OpenTofu does not see every out-of-band Harbor change | A replication filter edited in the Harbor UI stays unnoticed by `task harbor:plan` | Treat the Harbor UI as read-only; `tofu apply -replace` restores the declared rule |
