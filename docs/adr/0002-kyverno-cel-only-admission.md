# ADR 0002 — Kyverno CEL-only admission policies

- Status: accepted
- Scope: every admission policy under `policies/`

## Context

Admission must enforce the image chain of trust (keyless signature and attestations by the platform's
build workflow, a catalog-approved golden base read from the SLSA provenance, required labels, Harbor as
the only registry) and Pod Security Standards `restricted` in workload namespaces, report deviations in
platform namespaces, and be testable offline in CI. Kyverno 1.19 offers two policy families: the legacy
`ClusterPolicy`/`Policy` (deprecated, removed in Kyverno 1.20) and the CEL policy types
(`ValidatingPolicy`, `ImageValidatingPolicy`, `MutatingPolicy`) aligned with Kubernetes
`ValidatingAdmissionPolicy`. OPA Gatekeeper with Rego was the other candidate.

## Decision

- Every policy uses a Kyverno CEL policy type; nothing under `policies/` is a `ClusterPolicy` or `Policy`.
  Workload policies: `workload-image-signature`, `workload-golden-base`, `workload-registry`,
  `workload-image-labels` (`Deny`), `workload-golden-base-deprecated` (`Warn` + `Audit`) and the
  `workload-pod-security` MutatingPolicy that labels workload namespaces Pod Security `restricted`.
  Tier policies: `tier-label` (only platform administrators set `harborlab.io/tier`) and `tier-required`
  (every pod in a namespace without a valid tier is denied).
  Platform policies (`platform-registry-allow-list`, `platform-vendor-signatures`) only `Audit`.
- Pod Security `restricted` is native Pod Security Admission, not re-implemented as a policy.
- Policies read their parameters from generated ConfigMaps (`kyverno/golden-images` from
  `images/catalog.yaml`, `kyverno/harborlab-registries`), so a catalog change needs no policy change.
- `ImageValidatingPolicy` rewrites admitted workload images to their digest (`mutateDigest`).
- Deny policies run with `failurePolicy: Fail`; the deprecation warning runs with `Ignore`.
- Policies are tested with `kyverno test` (one suite per policy) and Chainsaw on an ephemeral kind cluster
  in CI on every pull request (`policies.yml` has no path filter on `pull_request`).

## Consequences

- The policies survive the removal of `ClusterPolicy` in Kyverno 1.20 and read like Kubernetes-native
  `ValidatingAdmissionPolicy` expressions.
- CEL policies report `fail`, never `warn`: the deprecated-base case is proven by the admission warning and
  a PolicyReport `fail` of an `Audit`/`Warn` policy.
- A denial by a CEL policy emits no Kubernetes event; admission violations are counted from the API server
  audit log instead.
- `kyverno test` deadlocks when two image-verifying policies evaluate the same resource
  (kyverno/sdk#125, see the [roadmap](../ROADMAP.md)), hence one test suite per policy.
- A Gatekeeper/Rego implementation of the same rules is kept as a roadmap comparison.
