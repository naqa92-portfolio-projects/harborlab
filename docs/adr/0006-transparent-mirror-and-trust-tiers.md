# ADR 0006 — Transparent registry mirror and trust tiers

- Status: accepted
- Scope: how nodes pull images and how much admission demands per namespace

## Context

Every pull should go through Harbor (proxy cache, scanning, one egress point), but Harbor itself, its
database, the CNI, the GitOps controller and the policy engine run on the same cluster: if they could only
pull through Harbor, a Harbor outage would prevent Harbor from restarting. Likewise, enforcing the full
workload chain of trust on the components that implement admission would create a dependency loop.

## Decision

- **Transparent mirror**: containerd on the kind node has `hosts.toml` mirrors for `docker.io`, `quay.io`,
  `ghcr.io`, `registry.k8s.io` and `dhi.io` pointing to the matching Harbor proxy-cache project, with the
  upstream registry as fallback. Manifests keep their original references; when Harbor is down the pull
  falls back upstream. Harbor is never a single point of failure and the bootstrap needs no special case.
- **Trust tiers** by namespace label:
  - `harborlab.io/tier=workload`: full chain enforced (build identity signature and attestations, catalog
    base, labels, Harbor `golden`/`apps` only, Pod Security `restricted`, digest pinning);
  - `harborlab.io/tier=platform`: registry allow-list and vendor signatures (Kyverno, Cilium, Argo CD)
    reported in `Audit` mode. The Cilium and Argo CD rules only apply to those images in a platform-tier
    namespace; here they run only in the excluded `cilium` and `argocd` namespaces, so in practice only
    Kyverno's images meet the rule;
  - no tier (a namespace without `harborlab.io/tier`, or with another value): every pod denied
    (`tier-required`), so a missing label never turns enforcement off;
  - bootstrap (`kube-system`, `cilium`, `argocd`, `kyverno`): excluded by name, documented in the
    [threat model](../THREAT-MODEL.md).

## Consequences

- Workloads must reference Harbor `golden`/`apps` explicitly; a mirror-served `docker.io` reference is still
  denied, since admission sees the reference, not the path of the pull.
- Platform components keep their upstream references and vendor signatures; their deviations are visible
  in PolicyReports without blocking recovery.
- The bootstrap exclusion is an accepted risk limited to cluster administrators.
- Proxy-cache fill is asynchronous and can trim multi-arch indexes (see ADR 0001).
