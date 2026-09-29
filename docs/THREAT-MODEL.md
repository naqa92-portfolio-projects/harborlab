# Threat model

harborlab governs which container images may run on the cluster. This document states what admission
trusts, per namespace tier, and the exceptions that trust relies on.

## Assets and threats

| Asset | Threat | Control |
|---|---|---|
| Workload images | Unsigned, tampered or foreign-built image deployed | Kyverno `workload-image-signature`: keyless signature and CycloneDX, SPDX and SLSA v1 attestations signed by the `build-image.yml` workflow identity, whose verified SLSA provenance names this repository as the caller (the reusable workflow signs with its own identity whoever calls it; its signing job also refuses to run for another repository) |
| Golden bases | Image built on an unknown or end-of-life base | Kyverno `workload-golden-base`: the base digest recorded in the verified SLSA provenance must be `supported` or `deprecated` in `images/catalog.yaml` (deprecated warns) |
| Registry path | Image pulled from outside the governed Harbor projects | Kyverno `workload-registry`: only `harbor.127.0.0.1.nip.io/golden/` and `/apps/` |
| Traceability | Image without source, revision or owner | Kyverno `workload-image-labels`: required OCI and `io.harborlab.*` labels |
| Node | Privileged or root container | Native Pod Security Admission, `restricted` enforced on every workload namespace by `workload-pod-security` |
| Tag drift | A tag re-pointed after admission | Admission rewrites every admitted workload image to its digest (`mutateDigest`) |

## Trust tiers

| Tier | Namespaces | Admission |
|---|---|---|
| Workload | labelled `harborlab.io/tier=workload` | Full chain, enforced (`Deny`): signature and attestations by the build identity, catalog-approved base, labels, Harbor `golden`/`apps` only, Pod Security `restricted`, digest pinning |
| Platform | labelled `harborlab.io/tier=platform` | Reported only (`Audit`): registry host in the platform allow-list; Kyverno, Cilium and Argo CD images verified against their vendor's keyless GitHub Actions identity (see below) |
| Bootstrap | `kube-system`, `cilium`, `argocd`, `kyverno` | None: excluded by name (see below) |
| None | any other namespace (no `harborlab.io/tier`, or another value) | Every pod denied (`tier-required`): enforcement fails closed, a missing label never turns the workload rules off |

Only platform administrators (cluster admins and Argo CD, which syncs the labels from git) set a tier:
anyone else allowed to edit namespaces can put a new or unlabelled one in the workload tier, but cannot
remove `harborlab.io/tier`, change it or choose `platform` (`tier-label`). The platform namespaces are
labelled in `platform/config/tiers/namespaces.yaml`, except `gateway` and `registry-mirror-test`, which
carry their label in their own manifests (`platform/config/gateway`, `platform/config/registry-mirror-test/dhi-pull.yaml`).

The Cilium and Argo CD vendor-signature rules only apply to those images when they run in a
platform-tier namespace. On this platform they run only in the excluded `cilium` and `argocd` namespaces, so in
practice only Kyverno's images (for example Policy Reporter's) meet the vendor-signature rule.

The allow-lists live in the ConfigMap `kyverno/harborlab-registries` (`policies/params/registries.yaml`)
and the golden catalog in `kyverno/golden-images`, generated from `images/catalog.yaml`.

## Bootstrap namespaces: explicit exclusion

The namespaces `kube-system`, `cilium`, `argocd` and `kyverno` are excluded by name from the platform and
tier policies, even when they carry a tier label. The workload policies select `harborlab.io/tier=workload`
only. They run the components admission itself depends on: the
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
identity (`build-image.yml` on this repository's `main` branch), and every signature is
recorded in the public Rekor transparency log. There is no long-lived private key to steal or rotate,
and the log makes every signing event auditable.

Trade-offs for a regulated environment such as a bank:

- Signing depends on the public Sigstore infrastructure (Fulcio, Rekor, TUF root) being reachable from CI
  and from admission.
- The transparency log publishes the signing identity, the repository and the image digest: acceptable
  for this public repository, not for confidential build metadata.
- Trust is anchored in the GitHub OIDC issuer and in write access to the repository: the identity
  `build-image.yml@refs/heads/main` of this repository is bound to whoever can push to `main` (the solo
  owner). The ruleset on `main` blocks deletion and force-pushes (`non_fast_forward`) so `main` cannot be
  rewritten or deleted, but it does not restrict who can push. Production trusts `main` only, so no rule on
  `prd-*` branches is needed.

## Environment-specific trust

The policies and the `dt-bridge` signer identities committed in git trust `build-image.yml` run from
`refs/heads/main` only (`dt-bridge` also accepts `golden.yml` for golden images). A platform deployed from
another revision (`task up` on a checked-out branch, or `HARBORLAB_REVISION=<revision>`) must also admit the
images that revision built before its merge, so it trusts exactly that one additional ref, and only in that
environment. The extra trust follows whatever revision is deployed, not only a `prd-*` branch (`main`, else
`HARBORLAB_REVISION`, else the current branch, else the `HEAD` SHA). A detached `HEAD` yields the identity `refs/heads/<sha>`, which matches
no real ref and adds no trust in practice.

- `task up` passes the revision to the root Application (`revision` value of `platform/apps`); off
  `main`, the Applications `kyverno-policies` and `dt-bridge` add a Kustomize patch whose identity is
  `refs/heads/(main|<revision>)`, the revision regexp-quoted. Never a pattern such as `prd-.+`: another
  branch of the repository stays untrusted.
- The policy CI (`kyverno test`, Chainsaw) renders the policies the same way for the branch under test
  with `scripts/render-policies.sh <revision> <out-dir>`, since its fixtures are signed on that branch.
- A platform deployed from `main` renders the committed identities unchanged.

A platform deployed from `main` right after a `prd-*` branch merges is the same situation from the other
side: the images its pins name (`images/catalog.yaml`'s `supported` digests, the app Dockerfile `FROM`
lines, `platform/workloads/*/*.yaml` and `images/demo-fixtures.yaml`) were signed on that `prd-*` branch,
which `main`'s committed identities no longer trust once it merges. `release-repin.yml` re-pins them, in
dependency order, on the pushes to `main` that can need it, opening a pull request per step instead of
pushing to `main` directly; see [README "After merging"](../README.md#after-merging) for the flow and
`devbox run -- task release:repin` for a manual run of the same steps. Never widen the committed identity
to also trust `prd-*` on `main` to work around this: any branch could then sign admissible images on
the environment every other consumer of the platform trusts by default, which the environment-specific
trust exists to avoid.

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
| Repository write access anchors the signing identity | The ruleset on `main` (a human setting, not declared in this repository) blocks deletion and force-pushes only; whoever has write access can push to `main` and sign admissible images, and that is the solo owner | A bank adds required reviews and required status checks on `main` and restricts who can push; `prd-*` needs no rule since production trusts `main` only |
| OpenTofu does not see every out-of-band Harbor change | A replication filter edited in the Harbor UI stays unnoticed by `task harbor:plan` | Treat the Harbor UI as read-only; `tofu apply -replace` restores the declared rule |
| `dt-bridge` reads attestations from Harbor referrers | A tampered referrer would mislead triage (not admission, which verifies signatures itself) | Fixed: `dt-bridge` verifies the Sigstore bundles against the build identity and the caller repository before using an attestation |
| The local CA once lacked a `keyUsage` extension | Strict X.509 clients rejected it, and `dt-bridge` relaxed Python's strict verification for Harbor | Fixed: `task up` emits a CA certificate with a critical `keyUsage` (`keyCertSign`, `cRLSign`), so strict verification stays on |
