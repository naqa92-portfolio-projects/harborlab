# Roadmap

## Upstream issues tracked

| Upstream issue | Impact on harborlab | Unblocks |
|---|---|---|
| [DependencyTrack/dependency-track#6132](https://github.com/DependencyTrack/dependency-track/issues/6132) — include associated source packages in vulnerability analysis for OS distro packages | Dependency-Track matches Debian OSV advisories (written on source packages such as `glibc`) by exact PURL name, while the attested SBOM lists binary packages (`libc6`) with an `upstream=` qualifier it ignores: no Debian finding exists in DT for golden images. | Finding-level proof of criterion 17 (DHI OpenVEX shown as `NOT_AFFECTED`), Debian coverage of criteria 18 and 21 in DT (PRD #1). |
| [DependencyTrack/dependency-track#6957](https://github.com/DependencyTrack/dependency-track/issues/6957) — Dependency-Track not matching Debian source-package vulnerabilities to binary packages | Same gap, reported on binary/source name divergence. | Same as #6132 (PRD #1). |
| [kyverno/sdk#125](https://github.com/kyverno/sdk/issues/125) (fix [kyverno/sdk#127](https://github.com/kyverno/sdk/pull/127)) — imagedataloader read lock leaked on cache hit | `kyverno test` deadlocks when two ImageValidatingPolicies evaluate the same resource; suites are split one policy per suite. | Optional merge of the per-policy `kyverno test` suites (PRD #1). |
