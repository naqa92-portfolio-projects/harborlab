# ADR 0003 — Kubescape over Trivy Operator and Falco for in-cluster scanning and runtime detection

- Status: accepted
- Scope: in-cluster vulnerability scanning, posture checks, runtime threat detection and runtime VEX

## Context

The platform needs, inside the cluster: a vulnerability scan of the running images, configuration
posture checks, runtime threat detection (a shell in a container must raise an alert) and, ideally,
reachability evidence that a vulnerable package is never loaded. The usual pair is Trivy Operator (scans,
posture) plus Falco (runtime rules), two operators with their own agents, rule languages and outputs,
on a single-node cluster with a 12 GiB memory budget.

## Decision

Deploy the Kubescape 4 operator instead of Trivy Operator and Falco:

- vulnerability scan of running images with Grype (`kubevuln`),
- CIS and NSA posture controls,
- runtime threat detection by the eBPF `node-agent` against container profiles (learned, or authored as
  for `runtime-demo`), alerts written as JSON log lines collected by VictoriaLogs,
- runtime OpenVEX documents (`OpenVulnerabilityExchangeContainer`, experimental) listing packages never
  loaded, forwarded by `dt-bridge` to Dependency-Track.

## Consequences

- One agent and one operator instead of two stacks, which fits the memory budget.
- The in-cluster scanner is Grype while the CI and Harbor scanner is Trivy: their CVE lists diverge
  (see [ADR 0008](0008-grype-and-trivy-divergence.md)); Dependency-Track is the triage source of truth.
- Runtime VEX generation is experimental: it needs about two minutes of observation per container and
  names images inconsistently (`docker.io` vs `index.docker.io`), which `dt-bridge` normalises.
- Runtime rules that compare behaviour with a profile stay silent until node-agent has loaded the
  container's profile; a learned profile only exists after the learning period, an authored one at once.
- Falco's large community rule set is not available; Kubescape's default rules cover the demo cases.
