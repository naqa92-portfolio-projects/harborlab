# ADR 0001 — Signature format, GHCR → Harbor replication and admission (M0 spike)

- Status: accepted
- Scope: every image signed in GitHub Actions, replicated into Harbor and admitted by Kyverno

## Context

Images are built in GitHub Actions, keyless-signed with cosign and attested (CycloneDX, SPDX,
SLSA provenance), pushed to GHCR, pull-replicated into Harbor, then admitted by a Kyverno
`ImageValidatingPolicy` on their Harbor reference. Two storage formats exist: cosign "classic"
tags (`sha256-<digest>.sig` / `.att`) and Sigstore bundles attached as OCI referrers. The spike
had to prove which one survives replication and is read by Kyverno.

Spike setup (`spike/`): kind v0.32 (containerd 2.3.1), Harbor 2.15.2 (chart 1.19.2), Kyverno
1.19.1 (chart 3.9.1), cosign 3.1.3, image `ghcr.io/naqa92-portfolio-projects/harborlab/spike/hello:m0`
published by `.github/workflows/spike.yml`.

## Decision

1. **Sigstore bundle format (cosign v3 default).** `cosign sign` / `cosign attest` run without
   format flags. Legacy `.sig`/`.att` tags are deprecated in cosign v3 (`--new-bundle-format` is
   marked "will be the only supported format"), so the platform does not build on them.
2. **SLSA provenance v1 predicate written by the workflow** and attached with
   `cosign attest --type slsaprovenance1`. It records the base image digest in
   `buildDefinition.resolvedDependencies`, which the catalog policy (M4) reads.
   `actions/attest-build-provenance` is not used: it stores to the GitHub attestations API and
   signs with a different identity than the workflow.
3. **Harbor replication copies the referrers fallback tag.** The pull-replication rule filters
   tags with `{<tag>,sha256-*}` and flattens the namespace (`dest_namespace_replace_count: -1`).
4. **Kyverno trusts Harbor's CA through `SSL_CERT_DIR`**, not through the chart's
   `caCertificates`.

## Findings

| Topic | Observed |
|---|---|
| GHCR storage | GHCR answers 404 on `/v2/<repo>/referrers/<digest>`. cosign therefore writes the referrers tag schema: tag `sha256-<hex>` = OCI index of `application/vnd.dev.sigstore.bundle.v0.3+json` manifests (one signature + one per attestation). |
| Replication | Harbor pull replication (adapter `github-ghcr`, anonymous, public package) copies `m0` with an identical digest. With the tag filter `{m0,sha256-*}` it also copies the fallback index; Harbor indexes the bundle manifests by their `subject` and serves them on its own referrers API. A filter on `m0` alone drops every signature and attestation. |
| cosign on Harbor | `cosign verify` and `cosign verify-attestation --type cyclonedx|spdxjson|slsaprovenance1` on `harbor…/spike/hello@<digest>` succeed with `--registry-cacert`; a foreign identity is rejected. cosign 3.1.3 auto-detects bundles and falls back to legacy tags when none exist. |
| Kyverno | `policies.kyverno.io/v1` `ImageValidatingPolicy` auto-detects the bundle format (`cosign.GetBundles`) and reads the signature and the three in-toto attestations through Harbor's referrers API. The unsigned image is denied; the denial message names the policy. |
| Kyverno trust | The chart's `caCertificates.data` replaces the image CA store. Adding the full system bundle to it overflows the 1 MiB Helm release Secret, and dropping it breaks Sigstore TUF/Rekor TLS. A ConfigMap mounted in `/etc/harbor-ca` plus `SSL_CERT_DIR=/etc/ssl/certs:/etc/harbor-ca` keeps both. |
| Name resolution | `harbor.127.0.0.1.nip.io` resolves to 127.0.0.1, i.e. the pod or node itself. Pods reach Harbor through a CoreDNS `rewrite name exact` to the Harbor Service; the kind node through an `/etc/hosts` entry to the Service ClusterIP. M1 (Cilium, Gateway API on the host network) replaces both. |
| containerd mirror | kind needs `config_path = "/etc/containerd/certs.d"`. `docker.io/hosts.toml` points to `https://harbor…/v2/dockerhub-proxy` with `override_path = true` and `server = "https://registry-1.docker.io"`. With Harbor scaled to 0 the Service has no endpoint, the connection is refused and the pull falls back upstream (~20 s). |
| Proxy cache fill | Asynchronous. containerd sends `HEAD` by tag then `GET` by digest. Per Harbor 2.15.2 `controller/proxy/manifestcache.go`, a platform manifest is stored ≥ 20 s after its blobs are fetched, after up to 10 × 20 s of waiting for blobs the client already had locally. For a multi-arch index pulled for one platform, Harbor waits up to 20 × 20 s for the other platforms, then pushes a **trimmed index with a new digest** and tags it. Measured for `busybox:1.36.1` pulled for amd64: the amd64 manifest is cached untagged, tag `1.36.1` appears only after ~5 min, on a trimmed index whose digest differs from Docker Hub's. |
| GHCR visibility | The spike package was pullable anonymously right after the first push (checked with an anonymous token). |

## Consequences

- Replication rules for `golden` and `apps` (M2) must include `sha256-*` in their tag filter.
- Registry clients and Kyverno need the platform CA; the CA is generated at runtime and never
  committed.
- A proxy-cache check that queries Harbor by tag must allow for the trimmed-index delay
  (minutes, not seconds), or check the platform manifest digest instead.
- Images that share layers already present on the node are cached late (≥ 200 s), since
  containerd does not fetch those layers through Harbor.
