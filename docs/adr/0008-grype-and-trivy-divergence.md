# ADR 0008 — Grype and Trivy scan results diverge; Dependency-Track is the triage source of truth

- Status: accepted
- Scope: which vulnerability counts are authoritative

## Context

Three scanners see the same images:

- Trivy in CI (`build-image.yml`, blocking, with the base image's VEX applied through `--vex oci`);
- Trivy in Harbor (scan on push, deployment security);
- Grype in the cluster (Kubescape `kubevuln`), on the running images.

Trivy and Grype use different vulnerability databases, matchers and distribution feeds, and they apply
VEX differently: their CVE lists for one image differ, sometimes by severity, sometimes by presence.
Dependency-Track matches the attested SBOM against its own sources.

## Decision

- Trivy remains the build gate (CI) and the registry gate (Harbor deployment security).
- Grype results stay Kubescape's own view of the running images; they are not reconciled with Trivy's.
- Dependency-Track, fed with the attested SBOM and the VEX documents by `dt-bridge`, is the triage source of
  truth; the `image posture` dashboard labels each CVE count with its source (`harbor-trivy`,
  `dependency-track`) before and after VEX.

## Consequences

- A CVE can block a build in Trivy and be absent from Grype, or the reverse; reviewers compare each tool on
  its own terms and triage in Dependency-Track.
- The dashboard never sums counts across scanners.
