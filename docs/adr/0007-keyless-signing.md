# ADR 0007 — Keyless signing with Sigstore and the GitHub OIDC identity

- Status: accepted
- Scope: signatures and attestations of golden, application and fixture images

## Context

Admission must prove that an image was built by the platform's workflow from this repository. Key-based
signing needs a private key stored, rotated and protected somewhere (a KMS or HSM in a bank); a public
portfolio repository has none of that. Sigstore keyless signing binds a short-lived Fulcio certificate to
the GitHub Actions OIDC identity of the workflow and records each signature in the Rekor transparency log.

## Decision

- `build-image.yml` signs and attests keyless with cosign v3 (Sigstore bundles as OCI referrers, see
  ADR 0001): signature, CycloneDX SBOM, SPDX SBOM and SLSA v1 provenance.
- Admission verifies the issuer `https://token.actions.githubusercontent.com` and the identity of
  `build-image.yml` in this repository on `main` or a `prd-*` branch.
- The DHI base signature is verified with DHI's public key before a golden image is built.

## Consequences

- No private key to manage; every signing event is public and auditable in Rekor.
- Signing and verification depend on the public Sigstore infrastructure (Fulcio, Rekor, TUF root).
- Whoever can push to `main` or create a `prd-*` branch can produce admissible images: repository write
  access is part of the trust chain (see the [threat model](../THREAT-MODEL.md)).
- A bank would sign with a KMS/HSM key or a private Sigstore; only the policies' attestor definition changes.

## Amendment (2026-09-28): main-only identity, repository binding, environment-specific revision trust

The original decision above (`main` or any `prd-*` branch trusted in production) let any `prd-*` branch
of this repository sign admissible images, which is stronger than intended for a production identity;
the decision it superseded here is kept as written above for its historical reasoning.

- **Main-only by default.** Committed policies and the `dt-bridge` signer identities now trust
  `build-image.yml` run from `refs/heads/main` only (`dt-bridge` also accepts `golden.yml` for golden
  images), not `refs/heads/prd-.+`. `prd-*` stays a development convenience, not a production trust anchor.
- **Repository binding.** `build-image.yml` is a public reusable workflow; without a caller check its
  Fulcio-issued SAN is identical whichever repository calls it. The build job now runs only when
  `github.repository == 'naqa92-portfolio-projects/harborlab'`. Admission additionally requires the caller
  repository in the verified SLSA provenance (`workload-image-signature`), and `dt-bridge` requires it in the
  certificate's source repository extension, so another repository invoking this workflow cannot produce an
  identity our admission or triage trusts.
- **Environment-specific revision trust.** A platform deployed from a non-`main` revision (`task up` on a
  checked-out branch, or `HARBORLAB_REVISION=<branch>`) must still admit the images that branch built
  before its merge. Off `main`, the root chart patches the `kyverno-policies` and `dt-bridge` Applications
  to also trust `refs/heads/(main|<revision>)`, the revision regexp-quoted — never a pattern such as
  `prd-.+` — and only in that one environment. The revision is whatever is deployed (`main`, else
  `HARBORLAB_REVISION`, else the current branch, else the `HEAD` SHA), not only a `prd-*` branch; a detached SHA yields `refs/heads/<sha>`, which matches no
  real ref. `scripts/render-policies.sh <revision> <out-dir>` renders the same identity for the policy CI. A platform deployed from `main` renders the committed identities
  unchanged. See the [threat model](../THREAT-MODEL.md#environment-specific-trust) for the full mechanism.
- **Repository ruleset.** The single ruleset on `main` blocks deletion and force-pushes
  (`non_fast_forward`); it does not restrict who can push. The identity `build-image.yml@refs/heads/main` of
  this repository is therefore bound to whoever has write access to it (the solo owner). The ruleset
  prevents rewriting or deleting `main`; since production trusts `main` only, no rule on `prd-*` branches is
  needed.
- **Build-only signing.** Signing and attestation steps in `build-image.yml` now run only on the
  digest this same job built (or, for an already-published tag, verify it was built and signed by this
  workflow before trusting it) — not on an arbitrary pre-existing GHCR tag pushed by any principal with
  `packages: write`.
- **Pinned DHI key.** The DHI base signature is verified against `.github/keys/dhi.pub`, a key
  pinned in this repository, instead of a key fetched from `dhi.io/keyring/latest.pub` at build time
  (which a compromised or unreachable `dhi.io` could substitute).

These changes narrow who can produce an admissible identity; they do not change the keyless mechanism
(Fulcio certificate bound to GitHub OIDC, logged in Rekor) the original decision adopted.
