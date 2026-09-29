# ADR 0005 — OpenTofu with the goharbor provider over harbor-cli for Harbor configuration

- Status: accepted (supersedes the initial choice of harbor-cli)
- Scope: Harbor projects, proxy caches, replications, robots, immutability, retention, webhooks and
  deployment security

## Context

Harbor itself is deployed by Argo CD from its Helm chart, but its configuration (projects, registry
endpoints, replication rules, robot accounts, tag immutability, retention, webhooks, deployment security)
lives in Harbor's database and API. It must be declarative, idempotent (a second run changes nothing) and
never write a secret to Git, to logs or to plain state. Three options were evaluated.

harbor-cli (pre-1.0) findings:

- no `--password-stdin` that works when piped, so the admin password ends up in argv or an interactive
  prompt;
- `robot create` prints the robot secret on stdout;
- missing features: no scheduled retention, no non-interactive immutability rule, no replication namespace
  flattening;
- imperative commands: idempotency would have to be scripted around list/compare/create.

Crossplane Harbor providers findings: the community providers are stale or single-maintainer, and a
Crossplane control plane costs memory on a budget-limited single node.

## Decision

- Harbor's configuration is OpenTofu code in `tofu/harbor`, using the official `goharbor/harbor` provider
  (OpenTofu and the provider pinned by devbox and the lock file), run by `task harbor:configure`;
  `task harbor:plan` exits 0 only when nothing would change.
- Robot secrets are generated in OpenBao and passed write-only (`secret_wo`, never in state).
- The state stays local, git-ignored and encrypted with the OpenBao Transit key provider.
- Replication filters name their repositories explicitly: Harbor's `github-ghcr` adapter cannot list
  GHCR repositories, so wildcard filters fail. The golden filter is derived from `images/catalog.yaml`; the `apps` filter is hard-coded.

## Consequences

- A second `task harbor:configure` has an empty plan; drift is visible with `task harbor:plan`.
- The registry credential of the `dhi.io` proxy cache and the webhook Bearer token have no write-only
  attribute: they are the secrets in the encrypted state.
- The provider does not detect every out-of-band change (replication filters edited in the UI are not seen
  as drift; `-replace` is needed).
- Rotating a robot secret requires bumping `secret_wo_version`.
