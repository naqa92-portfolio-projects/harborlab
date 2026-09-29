# Workarounds

Upstream limits the platform works around today. Each entry names the code that carries the
workaround, the upstream cause, and the condition under which the workaround can be removed.

## goharbor provider does not read back replication filter drift

`tofu/harbor/main.tf` builds `harbor_replication` filters (the `golden` name filter is derived from
`images/catalog.yaml`, the `apps` one is hard-coded, both in `harbor_replication.governed`) and, for the demo fixtures
replication, from two separate `filters` blocks — one `name`, one `tag` — because a single
`filters` block loses whichever attribute is not `name` when the provider drops filter attributes
other than `name`/`tag` from its own state read. Both issues mean OpenTofu's plan stays empty after
a filter is changed out of band (Harbor UI or API), or after only one of `name`/`tag` was set: `task
harbor:plan` shows no drift and `task harbor:configure` never repairs it; the operator must run
`tofu apply -replace=harbor_replication.<name>` by hand.

Upstream: [goharbor/terraform-provider-harbor#422](https://github.com/goharbor/terraform-provider-harbor/issues/422)
(`harbor_replications filter not working at all` — closed not planned).

Exit condition: the provider reads every filter attribute back into state (issue reopened/fixed and
released); until then `tofu/harbor/main.tf` keeps the two-block form and operators use `-replace`
for out-of-band filter changes.

## kyverno test deadlocks with more than one image-verifying policy per resource

`tests/kyverno/` runs one `kyverno-test.yaml` suite per policy instead of one suite per tier: the
`kyverno test` imagedataloader leaks its read lock on a cache hit, and two ImageValidatingPolicies
evaluating the same resource deadlock the CLI.

Upstream: [kyverno/sdk#125](https://github.com/kyverno/sdk/issues/125) (fix
[kyverno/sdk#127](https://github.com/kyverno/sdk/pull/127), open, unreleased).

Exit condition: `kyverno/sdk#127` (or an equivalent fix) ships in a released `kyverno` CLI; the
per-policy suites can then merge back into one suite per tier.

## Dependency-Track does not match Debian source-package advisories to binary packages

`apps/dt-bridge/src/dt_bridge/posture.py` and `apps/dt-bridge/src/dt_bridge/vex.py` convert DHI
OpenVEX `not_affected` statements (written on the upstream source package) to the SBOM's binary
component via its PURL `upstream=` qualifier, because Dependency-Track ignores that qualifier: a
Debian OSV advisory on `glibc` never matches the SBOM's `libc6` component, so no Debian finding
exists in DT to mark `NOT_AFFECTED`. Finding-level proof of golden-image VEX coverage is limited to
non-Debian ecosystems until DT itself resolves the mapping.

Upstream: [DependencyTrack/dependency-track#6132](https://github.com/DependencyTrack/dependency-track/issues/6132),
[DependencyTrack/dependency-track#6957](https://github.com/DependencyTrack/dependency-track/issues/6957).

Exit condition: either issue lands in a released Dependency-Track; `docs/ROADMAP.md` tracks the
unblock (finding-level VEX proof, Debian coverage).

## Kubescape storage lists ContainerProfiles without their spec

Kubescape's `kubescape/storage` API server returns `ContainerProfile` objects with metadata only on
a plain `kubectl get -o json` / list call; the `spec` (the statements dt-bridge and the runtime demo
need) is populated only when the request carries `resourceVersion=fullSpec`
(`pkg/registry/file/storage.go`). `platform/apps/templates/runtime-demo.yaml` also has Argo CD
ignore `/spec` on `ContainerProfile` (`ignoreDifferences`), so Argo CD cannot diff the spec. The spec is
authored in git (`platform/workloads/runtime-demo/containerprofile.yaml`), and the annotation
`harborlab.io/spec-sha256` (the SHA-256 of the canonical JSON of the spec) is the sync trigger: it must
change with the spec for a git change to sync. Nothing checks that the annotation matches the spec.

Upstream: no public issue found; behaviour observed directly in
`kubescape/storage`'s file-backed API server (undocumented `resourceVersion=fullSpec` requirement),
tracker at https://github.com/kubescape/storage/issues.

Exit condition: Kubescape documents or removes the `resourceVersion=fullSpec` requirement, or a
CRD-backed storage replaces the file-backed one; the ignoreDifferences entry can then be narrowed to
fields Kubescape truly does not own.

## node-agent readiness race on a freshly loaded runtime profile

`scripts/demo-runtime-shell.sh` can run the demo shell before Kubescape node-agent has loaded the
just-created/just-adopted `ContainerProfile` into its rule cache (its watch of the profile lags the
pod's own readiness by up to node-agent's one-minute reconcile tick). The script waits for
node-agent's own log line (`PROFILE_LOADED_MESSAGE`, "adopted user-authored ContainerProfile as
authoritative base") before running the shell, and re-runs a new shell if no alert follows within
`SHELL_ALERT_WAIT_SECONDS` instead of failing outright, since an unbound pod can silently drop the
first shell's syscalls.

Upstream: no public issue found; internal to Kubescape node-agent's profile-adoption timing, not
otherwise documented, tracker at https://github.com/kubescape/node-agent/issues.

Exit condition: node-agent exposes a readiness signal per pod/profile (e.g. a condition or metric)
that the demo can wait on directly instead of scraping logs and retrying; the retry loop in
`scripts/demo-runtime-shell.sh` can then be removed.

## Kubescape default rule bindings race a container's own start

`platform/apps/templates/kubescape.yaml` sets `nodeAgent.config.extra.ignoreRuleBindings: true` and
the runtime-demo target ships its own `ContainerProfile` (`platform/apps/templates/runtime-demo.yaml`)
instead of relying on Kubescape's automatic, generated one. Every enabled rule normally binds to
every container outside excluded namespaces from the container's start, but the binding is only
attached once node-agent's pod watch catches up (seconds after the container starts): on a freshly
recreated pod the first exec-in can happen before the automatic profile and its rule bindings exist,
so no alert fires. A user-authored `ContainerProfile`, adopted with `ignoreRuleBindings: true`, is
trusted as the authoritative rule set immediately instead of waiting on the generated one.

Upstream: no public issue found; internal to Kubescape node-agent's profile/binding reconcile order,
tracker at https://github.com/kubescape/node-agent/issues.

Exit condition: node-agent binds rules to a container no later than the container itself becomes
ready (ordering guarantee, not a race); `ignoreRuleBindings` and the user-authored profile can then
be dropped in favour of the generated one.

## hello-java forces `tomcat.version` above the Spring Boot BOM default

`apps/hello-java/pom.xml` sets `<tomcat.version>11.0.26</tomcat.version>`, above the
`spring-boot-starter-parent` BOM's managed Tomcat version, to close CVE-2026-65182. Renovate does
not track a bare `<properties>` override by itself, so a regex custom manager in `renovate.json`
(`hello-java Tomcat version forced in the Spring Boot BOM override`) tracks it against the `maven`
datasource for `org.apache.tomcat.embed:tomcat-embed-core`, alongside `apps/hello-java/pom.xml`.

Upstream: no public issue tracks this (an application-level CVE fix, not an upstream defect); the
Spring Boot BOM itself is tracked normally by Renovate's `maven` manager, upstream at
https://github.com/spring-projects/spring-boot/issues.

Exit condition: `spring-boot-starter-parent`'s managed Tomcat version reaches 11.0.26 or later on its
own (Renovate's normal Spring Boot bump would then carry Tomcat past the CVE fix); the property
override and its custom manager rule can be removed together.

## Kyverno `config.preserve: false`

`platform/apps/templates/kyverno.yaml:23` sets `config.preserve: false` on the Kyverno Helm release,
because the chart's post-delete hook keeps the Application out of sync and blocks Argo CD from pruning
it; the `kyverno` namespace's default `ConfigMap`/`Secret` are then pruned on an uninstall instead of
being left behind.

Upstream: not a defect, a deliberate chart default trade-off (the chart preserves that config by
default for clusters where Kyverno management is decoupled from its install lifecycle); chart at
https://github.com/kyverno/kyverno/issues.

Exit condition: none — this platform always installs and removes Kyverno through Argo CD, so nothing
depends on the config surviving an uninstall; kept as a documented, intentional deviation from the
chart default.

## Dependency-Track has no native OpenVEX import

`apps/dt-bridge/src/dt_bridge/vex.py` converts DHI and Kubescape OpenVEX documents to CycloneDX VEX
before uploading them to Dependency-Track, because DT accepts VEX only as CycloneDX; the whole
OpenVEX→CycloneDX conversion module exists only to bridge that gap and is isolated so it can be
deleted in one piece.

Upstream: [DependencyTrack/dependency-track#7094](https://github.com/DependencyTrack/dependency-track/issues/7094).

Exit condition: Dependency-Track accepts OpenVEX documents directly; `apps/dt-bridge/src/dt_bridge/vex.py`
is removed and DHI/Kubescape OpenVEX is uploaded to DT unconverted.

## CycloneDX has no justification for "cannot be controlled by an adversary"

`apps/dt-bridge/src/dt_bridge/vex.py:21` notes that CycloneDX's `analysis.justification` enum has no
equivalent to OpenVEX's `vulnerable_code_cannot_be_controlled_by_adversary`: the converter keeps that
label only in the free-text `details` field of the `not_affected` analysis instead of a structured
justification DT can filter or report on.

Upstream: [CycloneDX/specification#609](https://github.com/CycloneDX/specification/issues/609).

Exit condition: the CycloneDX specification adds an equivalent justification value (or DT accepts
OpenVEX natively, `docs/ROADMAP.md`); the converter can then emit a structured justification instead
of a details-only note.

## Harbor's github-ghcr adapter cannot list GHCR

`tofu/harbor/main.tf:41` (see the comment above `local.governed_projects`) builds explicit brace-glob
filters (`golden/{python,java}`, `apps/{dt-bridge,hello-java}`) for the GHCR pull replications,
because Harbor's `github-ghcr` registry adapter cannot list repositories under a GHCR owner: a
replication filter that would match "everything under this owner" silently replicates nothing.
Every governed repository name has to be named explicitly and kept in step with
`images/catalog.yaml`'s image names.

Upstream: no public issue found; observed directly against Harbor 2.x's `github-ghcr` adapter
(GHCR's package-listing API requires a PAT with different scopes than the adapter requests), tracker
at https://github.com/goharbor/harbor/issues.

Exit condition: the adapter gains the ability to list a GHCR owner's repositories (or Harbor adds a
GHCR-specific listing credential), so a single owner-level filter replaces the explicit name list.

## Harbor chart's proxy-cache registry types omit `quay`

`platform/apps/templates/harbor.yaml:55` sets the environment variable
`PERMITTED_REGISTRY_TYPES_FOR_PROXY_CACHE` to `docker-hub,harbor,azure-acr,ali-acr,aws-ecr,google-gcr,docker-registry,github-ghcr,jfrog-artifactory,quay`,
which overrides the chart's ConfigMap list of proxy-cache registry types because that list omits `quay`,
even though Harbor core itself supports a `quay` proxy-cache registry type; without the override, creating
a `quay` proxy-cache project through the chart-managed core fails validation.

Upstream: no public issue found against `goharbor/harbor-helm`; observed directly against the
chart's default `core.configureUserSettings`/env template, tracker at
https://github.com/goharbor/harbor-helm/issues.

Exit condition: the chart's default registry-type list includes `quay`; the env override in
`platform/apps/templates/harbor.yaml` can then be dropped.

## Policy Reporter UI's results API drops the `source` field

`tests/platform/observability.bats` filters Policy Reporter UI API calls with a `sources=` query
parameter instead of reading a `source` field on each result item, because the UI's results API does
not echo which policy engine (Kyverno, etc.) produced a result; `sources=` is the only way to prove
which source a result came from.

`platform/apps/templates/policy-reporter.yaml` separately ignores
`.spec.template.spec.containers[].image` on the Policy Reporter Deployment: the `vendor-signatures`
(platform tier) admission policy rewrites `ghcr.io/kyverno/*` image tags to their Kyverno-verified
digest, which Argo CD would otherwise report as permanent drift against the git-declared tag.

Upstream: no public issue found for either behaviour; observed directly against the Policy Reporter
UI API and its Helm chart's rendered Deployment, tracker at
https://github.com/kyverno/policy-reporter/issues.

Exit condition: Policy Reporter UI's results API includes a `source` field per result (the
`sources=` filter workaround can be dropped from the tests); the image-digest `ignoreDifferences`
entry has no exit condition — it documents an intentional consequence of `vendor-signatures` and
stays as long as that policy verifies Kyverno's own images.

## Cilium's Gateway API implementation rejects a port on a same-cluster HTTPRoute backend

`platform/workloads/dt-bridge/network-policy.yaml` (the `# Harbor through the Gateway` rule) grants
`dt-bridge`'s Cilium egress to the `harbor-core` endpoint with no `toPorts` restriction, because
Cilium's Gateway controller (`io.cilium/gateway-controller`) proxies Gateway-routed traffic through
Envoy, and Envoy checks the caller's egress policy against the real backend pod at L3 only for that
hop: a port restriction on this rule makes Envoy answer 403 on every request through the Gateway.

Upstream: no public issue found; observed directly against Cilium's Gateway API / Envoy integration
in this cluster's version, tracker at https://github.com/cilium/cilium/issues.

Exit condition: Cilium's Gateway implementation preserves the destination port when it checks egress
policy for Gateway-proxied traffic (matching plain pod-to-pod Cilium policy behaviour); the rule can
then be narrowed to the real backend port like every other egress rule in the file.

## Argo CD panics ("counter cannot decrease") when the host clock steps backward

Every Argo CD `Application` template under `platform/apps/templates/*.yaml` except `dt-bridge`,
`hello-java` and `runtime-demo` sets `syncOptions: [ServerSideApply=true]`, because Argo CD 3.5.3's client-side apply keeps a monotonic
resourceVersion-derived counter that panics when the WSL2 host clock steps backward (observed during
`task up`/`task down` cycles on a suspended/resumed WSL2 VM); server-side apply does not use that
counter. The workaround is not complete: an occasional manual `argocd app sync` is still needed after
a clock step (see the PRD `## State` gate notes).

Upstream: no public issue pinned (WSL2 clock-step interaction with Argo CD 3.5.3's internal counter,
not reproduced outside this environment); tracker at https://github.com/argoproj/argo-cd/issues.

Exit condition: Argo CD no longer panics on a clock step (fixed upstream, or this platform stops
running on a host whose clock can step backward); until then `ServerSideApply=true` stays the default
for the other Applications and a manual resync remains the documented recovery.

## Pull requests opened with `GITHUB_TOKEN` trigger no CI

`.github/workflows/golden.yml` and `.github/workflows/release-repin.yml` open pull requests with the
workflow `GITHUB_TOKEN`. GitHub does not start `pull_request` workflows for events created with that token,
so these pull requests run no `pull_request` CI. The `main` ruleset requires no status check, so they are not
blocked; the maintainer can trigger CI on the branch (an empty commit pushed by a person, or closing and
reopening the pull request).

Upstream: [GitHub documentation, triggering a workflow from a workflow](https://docs.github.com/en/actions/using-workflows/triggering-a-workflow#triggering-a-workflow-from-a-workflow).
If status checks become required, the standard remedy is to open these pull requests with a GitHub App
installation token.

Exit condition: the workflows open their pull requests with a GitHub App installation token, so CI runs
without a maintainer (needed only if checks become required).
