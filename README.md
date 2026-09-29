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
| A repository ruleset on `main` blocking deletion and force-pushes (`non_fast_forward`), nothing else: `main` cannot be rewritten or deleted, but anyone with write access can still push to it, so the signing identity `build-image.yml@refs/heads/main` is bound to whoever has write access to the repository (the solo owner). Production trusts `main` only, so no rule on `prd-*` branches is needed. A human sets this in repository settings, it is not automated | `gh api repos/{owner}/{repo}/rulesets` |
| A Docker account token for `dhi.io` in the git-ignored `.env` as `DHI_TOKEN`, with its account name as `DHI_USERNAME` | `grep -q '^DHI_TOKEN=.' .env && grep -q '^DHI_USERNAME=.' .env` |
| The same `DHI_TOKEN` and `DHI_USERNAME` as GitHub Actions secrets (golden image builds) | `gh secret list` |
| At least 16 GiB of RAM available to Docker (WSL included) | `free -g` |

The ruleset prevents rewriting or deleting this repository's `main`; it does not restrict who can push, and
it does not cover another repository calling `build-image.yml` as a reusable workflow — that caller is restricted
separately, by the `github.repository` job guard in `build-image.yml`.

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
then Argo CD deploys everything else from this repository at the checked-out branch, as pushed to `origin`
(`HARBORLAB_REVISION=<revision>` overrides the revision; unpushed local commits only raise a warning, since
Argo CD syncs the `origin` copy). It configures Harbor
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
| `task release:repin` | Re-pin the pins left behind by a merge to `main`, see "After merging" below |

## After merging

Admission and `dt-bridge` trust `build-image.yml@refs/heads/main` only (see "Environment-specific trust"
in the [threat model](docs/THREAT-MODEL.md)): a pull request built on a `prd-*` branch merges images
signed by that branch's own identity, which is untrusted once the branch is gone. `release-repin.yml`
brings every pin forward, in dependency order, on the pushes to `main` that can need it:

1. `dockerfiles`: once golden.yml's own `catalog` job has moved `images/catalog.yaml`'s `supported`
   digests, re-pins the app Dockerfile `FROM` lines built on them and opens a pull request.
2. `workloads`: once that pull request merges and `hello-java.yml` / `dt-bridge.yml` / `runtime-demo.yml`
   have rebuilt on the re-pinned base, re-pins `platform/workloads/*/*.yaml` to the images they published
   and opens a pull request.
3. `fixtures`: once `fixtures.yml` has published the admission fixtures for a commit on `main`, re-pins
   `images/demo-fixtures.yaml`'s commit and opens a pull request.
4. `e2e-params`: re-pins the E2E fixture Dockerfiles and the Kyverno E2E params to the `supported` catalog
   digests and opens a pull request. It has its own workflow, `release-repin-e2e.yml`, triggered by changes
   to those files and to `images/catalog.yaml`.

Each step is idempotent (a no-op pull request is never opened) and only ever opens a pull request: none
of them push to `main` directly. `devbox run -- task release:repin` runs the same four steps for the
current `HEAD`, for a manual re-pin (for example right after merging, without waiting for the app and
fixtures builds `release-repin.yml`'s later steps wait on).

Pull requests opened with the workflow `GITHUB_TOKEN` (`golden.yml`'s catalog pull request, the re-pin pull
requests) run no `pull_request` workflow; no status check is required, so they merge without one, and the
maintainer can trigger CI on the branch. If checks become required, the standard remedy, a GitHub App
installation token, is described in [Workarounds](docs/WORKAROUNDS.md).

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
10.0–10.4 GiB and the recorded peak is 10708 Mi, under the 12 GiB budget. `docker stats
harborlab-control-plane` shows the same cgroup from Docker's side and can differ from `kubectl top nodes`,
which is the reference. The platform components carry memory limits sized against this budget.
