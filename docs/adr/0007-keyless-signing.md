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
- Whoever can push to `main` or create a `prd-*` branch can produce admissible images: branch protection is
  part of the trust chain (see the [threat model](../THREAT-MODEL.md)).
- A bank would sign with a KMS/HSM key or a private Sigstore; only the policies' attestor definition changes.
