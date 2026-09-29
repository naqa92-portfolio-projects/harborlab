# Demo runbook

Each governance scenario is one Task, run from the repository root on a running platform (`task up`):

```sh
devbox run -- task demo:<scenario>
```

A scenario exits 0 when the platform reacts as documented below, and non-zero otherwise: a scenario that
exits 0 has observed the reaction, not merely submitted something. Every task uses the platform kubeconfig
`.kube/harborlab.yaml` itself.

## Admission scenarios

The seven admission scenarios submit one pod named `demo-<scenario>` (replacing a previous pod of that
name) into the namespace given by the Taskfile variable `NAMESPACE`, default `runtime-demo`, a workload
namespace (`harborlab.io/tier=workload`) provided by the platform. The task first prints
`demo:<scenario> target: <namespace>/<pod> image: <image>`, then the API server's answer (denial message
or `Warning:` lines). It never creates, labels or deletes the namespace.

```sh
devbox run -- task demo:unsigned                                   # default workload namespace
kubectl create namespace scratch
devbox run -- task demo:unsigned NAMESPACE=scratch                 # no tier label: denied by tier-required, exits 0
```

The pod is otherwise compliant with Pod Security `restricted`, so that only the rule under demo reacts.
Run in a namespace without a `harborlab.io/tier` label, whatever the scenario, the pod is denied by
`tier-required` (`Policy tier-required failed: pods run only in a namespace labelled
harborlab.io/tier=workload or harborlab.io/tier=platform`) and the task exits 0: the denial is the
documented outcome there, and it comes from the platform's tiering, not from the pod.

The images of the Harbor-based scenarios are the admission fixtures of `tests/fixtures/images`, built by
`.github/workflows/fixtures.yml` and pulled into Harbor `apps` by the replication
`apps-demo-fixtures-from-ghcr` (run on demand by the task when an image is missing).

### `demo:unsigned` — an image nobody signed

- Image: `harbor.127.0.0.1.nip.io/apps/unsigned` — the compliant fixture's digest, copied without any
  signature or attestation.
- Reaction: denied by `workload-image-signature`:
  `Policy workload-image-signature failed: image is not signed by the harborlab build-image workflow`.
- Check yourself: `cosign verify` of the image fails for any identity.

### `demo:foreign-signer` — signed, but not by the platform

- Image: `harbor.127.0.0.1.nip.io/apps/foreign-signer` — same digest, keyless-signed and attested by the
  fixtures workflow's own identity instead of `build-image.yml`.
- Reaction: denied by `workload-image-signature`, same message as `demo:unsigned`: a valid signature from
  the wrong identity is no signature.

### `demo:non-golden-base` — built on a base outside the catalog

- Image: `harbor.127.0.0.1.nip.io/apps/unknown-base` — built and signed by `build-image.yml`, directly on a
  Docker Hardened Image instead of a golden image; its SLSA provenance names that base.
- Reaction: denied by `workload-golden-base`:
  `Policy workload-golden-base failed: image base is not a golden image of the catalog`.

### `demo:deprecated-base` — built on a deprecated golden image

- Image: `harbor.127.0.0.1.nip.io/apps/demo-deprecated-base` — built by `build-image.yml` on the golden
  python 3.10, which `images/catalog.yaml` marks `deprecated`.
- Reaction: admitted with a warning. The API server answers with a `Warning:` line naming
  `workload-golden-base-deprecated` (`image base is a deprecated golden image`), the pod is created with
  its image rewritten to a Harbor digest, and its PolicyReport holds the `fail` result of that `Audit`/`Warn`
  policy.

### `demo:eol-base` — built on an end-of-life golden image

- Image: `harbor.127.0.0.1.nip.io/apps/demo-eol-base` — built by `build-image.yml` on the golden java 26,
  which `images/catalog.yaml` marks `eol` (end-of-life).
- Reaction: denied by `workload-golden-base`:
  `Policy workload-golden-base failed: image base is an end-of-life golden image`.

### `demo:direct-dockerhub` — pulled straight from Docker Hub

- Image: `docker.io/library/busybox:1.37.0`, pinned by digest.
- Reaction: denied by `workload-registry`:
  `Policy workload-registry failed: image is not served from an allowed workload registry`. Workloads
  must name Harbor `golden`/`apps`, even though the node would pull Docker Hub through the Harbor proxy
  cache.

### `demo:root` — a pod running as root

- Image: the governed `runtime-demo` image (Harbor `apps`), admissible by every Kyverno policy.
- Pod: `runAsUser: 0`.
- Reaction: denied by Pod Security Admission, profile `restricted` enforced on every workload namespace:
  `violates PodSecurity "restricted:latest"`.

## `demo:runtime-shell` — a shell in a running workload

- Target: the `runtime-demo` Deployment (namespace `runtime-demo`, a governed Harbor image that carries a
  shell). Its pods carry `kubescape.io/user-defined-profile: runtime-demo`: Kubescape's node-agent enforces
  the authored ContainerProfile `runtime-demo-runtime-demo` (its normal processes, files, syscalls and capabilities) from
  container start, instead of learning a profile first.
  node-agent applies every enabled rule to every monitored container from its start
  (`ignoreRuleBindings`), so the profile is the only thing a new container waits for.
- The task waits until node-agent reports it has loaded that profile for the current container (its log
  line `adopted user-authored ContainerProfile as authoritative base`, from node-agent's log or, once
  rotated, VictoriaLogs), runs
  `sh -c 'echo …'` with `kubectl exec` (again every 10 s until an alert shows, within a 120 s budget),
  prints `runtime-shell target: <namespace>/<pod>/<container>`,
  then waits for the Kubescape alert of that shell and prints `runtime-shell alert: <alert>`.
- Reaction: Kubescape raises `Unexpected process launched` (rule `R0001`) for the shell. The alert is in
  VictoriaLogs within seconds; in Grafana, open *Explore*, datasource `victorialogs`, and query
  `RuleID:R0001 AND RuntimeK8sDetails.namespace:="runtime-demo"`. The `image posture` dashboard's runtime
  panel counts it for golden image `python`.
- The task exits non-zero when node-agent has not loaded the profile within 90 s (it retries a failed
  profile fetch every minute) or no alert comes within the 120 s budget.

## `demo:vex` — vendor VEX reaches Dependency-Track

- The task replays, to `dt-bridge`, the Harbor push event of the first golden image of
  `images/catalog.yaml` at its Harbor tag. `dt-bridge` uploads the image's attested CycloneDX SBOM to
  Dependency-Track (project `golden/<name>`, version = tag), reads the DHI base from the verified SLSA
  provenance, converts the DHI OpenVEX statements of that base into a CycloneDX VEX on the SBOM's
  components, waits for Dependency-Track's analysis and uploads the VEX.
- Reaction: Dependency-Track accepts the VEX and processes it; the task polls the upload token until
  Dependency-Track reports it `COMPLETED`, then prints `vex accepted: golden/<name>:<tag> token <token>`.
  It exits non-zero when the token ends `FAILED`, or when no upload or completion happens in time.
- Limit: the analysis of each finding is not claimed. Dependency-Track matches Debian advisories by source
  package while the SBOM lists binary packages, so no Debian finding exists for the golden images and the
  DHI statements cannot show as finding-level analyses until DependencyTrack/dependency-track#6132 is
  resolved (see the [roadmap](ROADMAP.md)).
