# harborlab

A container image governance platform on a single kind cluster: golden images built on Docker Hardened
Images, a reusable build workflow that signs and attests every image, Harbor as the governed registry,
Kyverno admission per trust tier, Kubescape runtime detection, Dependency-Track triage and an image
posture dashboard. Applications only write `FROM <golden image>` and one `uses:` line; the platform owns
the rest (build, attestation, registry, admission, runtime detection and triage).

- [Architecture](docs/ARCHITECTURE.md): components, image flow and trust tiers.
- [Threat model](docs/THREAT-MODEL.md): what admission trusts and the accepted exceptions.
- [Demo runbook](docs/DEMO.md): the `task demo:*` scenarios and the reaction each one proves.
- [Architecture decision records](docs/adr/): one per structuring decision.
- [Roadmap](docs/ROADMAP.md): out-of-scope items and tracked upstream issues.
- [Golden image catalog](docs/golden-images.md): generated from `images/catalog.yaml`.

## Prerequisites

| Requirement | Check |
|---|---|
| [devbox](https://www.jetify.com/devbox) installed: it pins every CLI (kind, kubectl, Helm, cosign, OpenTofu, Kyverno, Task…) | `command -v devbox` |
| Docker daemon running (kind runs the cluster as a Docker container) | `docker info >/dev/null 2>&1` |
| GitHub CLI (`gh`) logged in | `gh auth status` |
| Public repository: keyless signing identity, public GHCR images, OpenSSF Scorecard | `gh repo view --json visibility -q .visibility` |
| A repository ruleset protecting `main` (required reviews, required status checks, no force-push/deletion) and restricting who can create `prd-*` branches, so the signing identity (`build-image.yml@refs/heads/main`, plus the one deployed `prd-*` branch) is only as trusted as who can push those refs — a human sets this in repository settings, it is not automated | `gh api repos/{owner}/{repo}/rulesets` |
| A Docker account token for `dhi.io` in the git-ignored `.env` as `DHI_TOKEN`, with its account name as `DHI_USERNAME` | `grep -q '^DHI_TOKEN=.' .env && grep -q '^DHI_USERNAME=.' .env` |
| The same `DHI_TOKEN` and `DHI_USERNAME` as GitHub Actions secrets (golden image builds) | `gh secret list` |
| At least 16 GiB of RAM available to Docker (WSL included) | `free -g` |

The ruleset protects who can push to this repository's own `main`/`prd-*` refs; it does not cover
another repository calling `build-image.yml` as a reusable workflow — that caller is restricted
separately, by the `github.repository` job guard in `build-image.yml` (R2).

`.env` is git-ignored and only read by the Taskfile; `task up` seeds its values into OpenBao, from where
External Secrets delivers them to the cluster. Never commit it.

```sh
cat > .env <<'EOF'
DHI_USERNAME=<docker account name>
DHI_TOKEN=<docker access token with dhi.io pull scope>
EOF
chmod 600 .env
```

## Start and stop

```sh
devbox run -- task up     # create or converge the cluster; returns once every Argo CD Application is stable
devbox run -- task down   # delete the cluster and its isolated kubeconfig
```

`task up` creates the kind cluster `harborlab` with a kubeconfig of its own, `.kube/harborlab.yaml`
(git-ignored; `export KUBECONFIG=$PWD/.kube/harborlab.yaml`). It installs Cilium and Argo CD with Helm,
then Argo CD deploys everything else from this repository at the checked-out branch. It configures Harbor
with OpenTofu (`task harbor:configure`), replicates the golden and application images from GHCR, and exits
0 only after every Argo CD Application has been Synced and Healthy for 60 consecutive seconds. A fresh
run takes about 15 minutes.

The platform is not built to survive a stopped node: after `docker stop harborlab-control-plane`, a
host reboot or a Docker restart, OpenBao comes back sealed and controllers such as the Kyverno reports
controller or Argo CD may not reconverge on their own. Recover by rebuilding the cluster with
`devbox run -- task down && devbox run -- task up` (`task down && task up`); the local CA in `.local/ca/`
is kept, every other credential is generated anew.

Web interfaces, all under the local CA generated in `.local/ca/` (import `ca.crt` in the browser):

| Service | URL | Credentials |
|---|---|---|
| Harbor | `https://harbor.127.0.0.1.nip.io` | `admin`, password in Secret `harbor/harbor-admin` |
| Argo CD | `https://argocd.127.0.0.1.nip.io` | `admin`, password in Secret `argocd/argocd-initial-admin-secret` |
| Dependency-Track | `https://dependency-track.127.0.0.1.nip.io` | `admin`, password in OpenBao `secret/platform/dependency-track-admin` |
| Grafana | `https://grafana.127.0.0.1.nip.io` | `admin`, password in Secret `observability/grafana-admin` |
| Policy Reporter | `https://policy-reporter.127.0.0.1.nip.io` | none |

## Everyday tasks

| Task | What it does |
|---|---|
| `task harbor:configure` / `task harbor:plan` | Apply / plan the OpenTofu Harbor configuration (`tofu/harbor`) |
| `task catalog:generate` / `task catalog:check` | Regenerate / check the Kyverno params and catalog doc from `images/catalog.yaml` |
| `task lint` | The platform lint the CI runs on every pull request |
| `task demo:<scenario>` | One governance scenario, see [the demo runbook](docs/DEMO.md) |

## Memory budget

With every component running, the cluster stays at or below **12 GiB** of memory. The figure is the
node's working set as the Kubernetes metrics pipeline reports it:

```sh
export KUBECONFIG=$PWD/.kube/harborlab.yaml
kubectl top nodes
```

`kubectl top nodes` reports the working set of the kind node (metrics-server reading the kubelet's
cgroup statistics): resident memory plus the active page cache, which the kernel does not reclaim first.
Page cache is a large share here: containerd's image layers, the Kubescape Grype vulnerability database
and the PostgreSQL buffers of Harbor and Dependency-Track all sit in it. A fresh platform measures about
10.0–10.4 GiB, under the 12 GiB budget. `docker stats harborlab-control-plane` shows the same cgroup from
Docker's side and can differ from `kubectl top nodes`, which is the reference. The platform components
carry memory limits sized against this budget.
