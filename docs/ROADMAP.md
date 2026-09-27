# Roadmap

## Out of scope for the first version

| Item | Why it matters | Direction |
|---|---|---|
| Air-gap bundle | Regulated sites run disconnected clusters: every chart, image, signature, attestation, SBOM, VEX, Sigstore trusted root and vulnerability database must be carried in | One OCI bundle per release (images with their referrers, charts as OCI artifacts, a TUF/Sigstore trusted root snapshot, Trivy/Grype databases), imported into Harbor and verified before use; admission then verifies against the offline trusted root |
| Gatekeeper and Rego comparison | Many banks already run OPA Gatekeeper; the choice of Kyverno CEL (ADR 0002) should be backed by a side-by-side | Re-implement the workload rules as Gatekeeper constraint templates in Rego (with an external data provider for signature verification, e.g. Ratify) and compare expressiveness, image verification, test tooling and resource cost |
| Buildah builds | Rootless, daemonless builds (Buildah or Podman) are common where Docker is not allowed on build agents | A `build-image.yml` variant building with Buildah, keeping the same SBOM, provenance, scan and signing steps, so admission cannot tell the builder apart |
| Chart relocation as OCI | Helm charts are pulled from upstream repositories at sync time, outside Harbor governance | Relocate every chart into Harbor as an OCI artifact (signed, scanned, immutable) and point the Argo CD Applications at `oci://harbor…`, the chart counterpart of image replication |

## Upstream issues tracked

| Upstream issue | Impact on harborlab | Unblocks |
|---|---|---|
| [DependencyTrack/dependency-track#6132](https://github.com/DependencyTrack/dependency-track/issues/6132) — include associated source packages in vulnerability analysis for OS distro packages | Dependency-Track matches Debian OSV advisories (written on source packages such as `glibc`) by exact PURL name, while the attested SBOM lists binary packages (`libc6`) with an `upstream=` qualifier it ignores: no Debian finding exists in DT for golden images. | Finding-level proof of criterion 17 (DHI OpenVEX shown as `NOT_AFFECTED`), Debian coverage of criteria 18 and 21 in DT (PRD #1). |
| [DependencyTrack/dependency-track#6957](https://github.com/DependencyTrack/dependency-track/issues/6957) — Dependency-Track not matching Debian source-package vulnerabilities to binary packages | Same gap, reported on binary/source name divergence. | Same as #6132 (PRD #1). |
| [kyverno/sdk#125](https://github.com/kyverno/sdk/issues/125) (fix [kyverno/sdk#127](https://github.com/kyverno/sdk/pull/127)) — imagedataloader read lock leaked on cache hit | `kyverno test` deadlocks when two ImageValidatingPolicies evaluate the same resource; suites are split one policy per suite. | Optional merge of the per-policy `kyverno test` suites (PRD #1). |
