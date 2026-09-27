# ADR 0004 — Dependency-Track with dt-bridge for vulnerability triage

- Status: accepted
- Scope: SBOM storage, vulnerability triage and VEX handling

## Context

Every image carries a CycloneDX SBOM attested at build time, and its golden base comes with vendor
OpenVEX statements (Docker Hardened Images publish `not_affected` statements as OCI referrers). Kubescape
produces runtime OpenVEX documents. Triage needs one place where findings per image version are listed and
VEX analyses applied, fed with the attested SBOM rather than a regenerated one. Dependency-Track 5.1
imports CycloneDX SBOMs and CycloneDX VEX, not OpenVEX (DependencyTrack/dependency-track#7094), and has
no Harbor integration.

## Decision

- Dependency-Track 5.1 on CloudNativePG is the triage source of truth.
- `dt-bridge`, a small Python (FastAPI) service built through the golden path itself, connects it:
  - on each Harbor webhook (push or replication into `golden`/`apps`) it reads the image's CycloneDX
    attestation from Harbor's referrers, extracts the SBOM unchanged and uploads it to project
    `<harbor project>/<repository>`, version = tag;
  - it reads the DHI base from the verified SLSA provenance, fetches that base's DHI OpenVEX, converts its
    `not_affected` statements to a CycloneDX VEX on the attested SBOM's components (Debian source packages
    resolved to their binary packages) and uploads it once Dependency-Track has analysed the SBOM;
  - it forwards Kubescape runtime OpenVEX documents the same way;
  - it exports the image posture metrics of the Grafana dashboard.
- The OpenVEX vocabulary is read in one module (`vex.py`), removable once Dependency-Track imports OpenVEX.

## Consequences

- SBOMs in Dependency-Track are exactly those attested and signed at build time.
- Dependency-Track matches Debian advisories by source package name while the SBOM lists binary packages
  with an `upstream=` qualifier it ignores (DependencyTrack/dependency-track#6132, #6957): no Debian finding
  exists for golden images, so the finding-level `NOT_AFFECTED` analysis of a DHI statement is not
  observable yet. The VEX upload itself is accepted and processed (`COMPLETED`).
- `dt-bridge` is a platform component to maintain, with its own unit tests (pytest, fixed fixtures).
