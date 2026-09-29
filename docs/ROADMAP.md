# Roadmap

## Out of scope for the first version

| Item | Why it matters | Direction |
|---|---|---|
| Air-gap bundle | Regulated sites run disconnected clusters: every chart, image, signature, attestation, SBOM, VEX, Sigstore trusted root and vulnerability database must be carried in | One OCI bundle per release (images with their referrers, charts as OCI artifacts, a TUF/Sigstore trusted root snapshot, Trivy/Grype databases), imported into Harbor and verified before use; admission then verifies against the offline trusted root |
| Gatekeeper and Rego comparison | Many banks already run OPA Gatekeeper; the choice of Kyverno CEL (ADR 0002) should be backed by a side-by-side | Re-implement the workload rules as Gatekeeper constraint templates in Rego (with an external data provider for signature verification, e.g. Ratify) and compare expressiveness, image verification, test tooling and resource cost |
| Buildah builds | Rootless, daemonless builds (Buildah or Podman) are common where Docker is not allowed on build agents | A `build-image.yml` variant building with Buildah, keeping the same SBOM, provenance, scan and signing steps, so admission cannot tell the builder apart |
| Chart relocation as OCI | Helm charts are pulled from upstream repositories at sync time, outside Harbor governance | Relocate every chart into Harbor as an OCI artifact (signed, scanned, immutable) and point the Argo CD Applications at `oci://harbor…`, the chart counterpart of image replication |

## Known debt after the first version

| Item | Why it matters | Direction |
|---|---|---|
| Re-pin pull requests run no CI | Pull requests opened by `golden.yml` and `release-repin*.yml` with `GITHUB_TOKEN` trigger no `pull_request` workflow, so digest bumps merge unchecked | Open them with a GitHub App installation token (`actions/create-github-app-token`), then make the CI checks required on `main` |
| Unsigned tag after a failed build | `build-image.yml` pushes before Trivy and signing; a failure leaves an unsigned tag that re-runs never re-sign, so the commit must change | Push by digest only after scan and signature pass, or re-sign a verified own-built digest on re-run |
| dt-bridge delivery guarantees | Forwarded-VEX state lives in memory (a restart resends everything), failed uploads are not retried, and events beyond the 200-SBOM queue are dropped with a 503 | Persist delivery state, retry with backoff, let Harbor redeliver instead of dropping |
| Node restart resilience | After a stopped kind node, OpenBao comes back sealed and some controllers do not reconverge; recovery is `task down && task up` | Auto-unseal (Transit or static seal) and readiness-gated restarts of the controllers that lose their leases |
| Policy Reporter `error` results | Every namespace carries one `error` result for the Kyverno ImageValidatingPolicies, with no visible cause | Find which policy/resource pair errors (Kyverno background scan) and fix or exclude it |
| Deprecated-base warning shown as `fail` | CEL policies report the deprecated golden base as `fail` in PolicyReports while admission shows a Warning | Report it as `warn` (policy `validationActions`/reporting mapping) so dashboards match the admission outcome |
| Posture dashboard and consoles ergonomics | Truncated panel titles, runtime alert panel dominated by anomaly noise, image-independent rules counted per image, Harbor typing SBOM/provenance accessories as `signature.cosign`, Dependency-Track project list flooded with versions | Dashboard layout pass; filter runtime rules; mark older DT project versions inactive on each new version |
| Grafana memory headroom | Explore on VictoriaLogs peaks at ~640 Mi for a 768 Mi limit | Re-measure after Grafana upgrades; raise the limit within the 12 GiB budget if the peak grows |
| Vendor signatures on platform images | Cilium and Argo CD images run only in excluded bootstrap namespaces, so their vendor-signature rules never meet a real pod | Admit those components through a verified path (image verification at bootstrap, or moving them out of the excluded tier once Kyverno is up) |

## Upstream issues tracked

| Upstream issue | Impact on harborlab | Unblocks |
|---|---|---|
| [DependencyTrack/dependency-track#6132](https://github.com/DependencyTrack/dependency-track/issues/6132) — include associated source packages in vulnerability analysis for OS distro packages | Dependency-Track matches Debian OSV advisories (written on source packages such as `glibc`) by exact PURL name, while the attested SBOM lists binary packages (`libc6`) with an `upstream=` qualifier it ignores: no Debian finding exists in DT for golden images. | Finding-level proof of criterion 17 (DHI OpenVEX shown as `NOT_AFFECTED`), Debian coverage of criteria 18 and 21 in DT (PRD #1). |
| [DependencyTrack/dependency-track#6957](https://github.com/DependencyTrack/dependency-track/issues/6957) — Dependency-Track not matching Debian source-package vulnerabilities to binary packages | Same gap, reported on binary/source name divergence. | Same as #6132 (PRD #1). |
| [kyverno/sdk#125](https://github.com/kyverno/sdk/issues/125) (fix [kyverno/sdk#127](https://github.com/kyverno/sdk/pull/127)) — imagedataloader read lock leaked on cache hit | `kyverno test` deadlocks when two ImageValidatingPolicies evaluate the same resource; suites are split one policy per suite. | Optional merge of the per-policy `kyverno test` suites (PRD #1). |
