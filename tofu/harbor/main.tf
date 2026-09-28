locals {
  harbor_url = "https://harbor.127.0.0.1.nip.io"

  # Proxy-cache project per upstream, keyed by registry endpoint name; `type` is the provider
  # name (`github` is the Harbor type `github-ghcr`).
  proxy_caches = {
    dockerhub = { project = "dockerhub-proxy", type = "docker-hub", url = "https://hub.docker.com" }
    quay      = { project = "quay-proxy", type = "quay", url = "https://quay.io" }
    ghcr      = { project = "ghcr-proxy", type = "github", url = "https://ghcr.io" }
    k8s       = { project = "k8s-proxy", type = "docker-registry", url = "https://registry.k8s.io" }
    dhi       = { project = "dhi-proxy", type = "docker-registry", url = "https://dhi.io" }
  }

  catalog = yamldecode(file("${path.module}/../../images/catalog.yaml"))

  # Golden repositories in images/catalog.yaml order, the catalog being their single source.
  golden_names = distinct([for image in local.catalog.images : image.name])

  # Digests the platform runs or admits: the catalog golden images and the Harbor images of the workload
  # manifests, keyed "<project>/<repository>@<digest>".
  workloads_dir = "${path.module}/../../platform/workloads"
  workload_image_refs = distinct(flatten([
    for f in fileset(local.workloads_dir, "**/*.yaml") : [
      for ref in regexall(
        "${replace(trimprefix(local.harbor_url, "https://"), ".", "\\.")}/(golden|apps)/([a-z0-9._/-]+)@(sha256:[0-9a-f]{64})",
        file("${local.workloads_dir}/${f}")
      ) : "${ref[0]}/${ref[1]}@${ref[2]}"
    ]
  ]))
  pinned_images = merge(
    { for image in local.catalog.images : "golden/${image.name}@${image.digest}" => {
      project = "golden", repository = image.name, digest = image.digest
    } },
    { for ref in local.workload_image_refs : ref => {
      project    = split("/", ref)[0]
      repository = trimprefix(split("@", ref)[0], "${split("/", ref)[0]}/")
      digest     = split("@", ref)[1]
    } },
  )

  # Governed projects, pulled from GHCR. Harbor's github-ghcr adapter cannot list GHCR repositories:
  # a wildcard name filter fails every execution, so each filter names its repositories. No tag
  # filter: the cosign referrers fallback tags (sha256-*) are replicated with the images.
  governed_projects = {
    golden = { ghcr_filter = "naqa92-portfolio-projects/harborlab/golden/{${join(",", local.golden_names)}}" }
    apps   = { ghcr_filter = "naqa92-portfolio-projects/harborlab/apps/{dt-bridge,hello-java}" }
  }

  # The runtime-detection demo target lands in `apps` through its own policy, apart from the applications.
  runtime_demo_filter = "naqa92-portfolio-projects/harborlab/apps/runtime-demo"

  # Non-compliant admission fixtures the `task demo:*` scenarios submit from Harbor `apps`, where only
  # admission can reject them (flattened: fixtures/unsigned lands as apps/unsigned).
  demo_fixtures_filter = "naqa92-portfolio-projects/harborlab/fixtures/{unsigned,foreign-signer,unknown-base,demo-deprecated-base,demo-eol-base}"

  # Harbor cron expressions carry a leading seconds field.
  replication_cron = "0 */15 * * * *"
  retention_cron   = "0 0 3 * * *"

  webhook_address = "http://dt-bridge.dt-bridge.svc.cluster.local:8080/harbor/events"

  dt_bridge_access = [
    { resource = "repository", action = "pull" },
    { resource = "repository", action = "list" },
    { resource = "artifact", action = "read" },
    { resource = "artifact", action = "list" },
    { resource = "tag", action = "list" },
    { resource = "accessory", action = "list" },
  ]
}

# The dhi.io credential has no write-only variant: the encrypted state holds it.
data "vault_kv_secret_v2" "dhi" {
  mount = "secret"
  name  = "platform/dhi"
}

# harbor_project_webhook.auth_header has no write-only variant either: the webhook secret is held by the
# encrypted state, and shown as sensitive in plans.
data "vault_kv_secret_v2" "webhook_dt_bridge" {
  mount = "secret"
  name  = "platform/harbor-webhook-dt-bridge"
}

ephemeral "vault_kv_secret_v2" "robot_dt_bridge" {
  mount = "secret"
  name  = "platform/harbor-robot-dt-bridge"
}

resource "harbor_registry" "proxy" {
  for_each = local.proxy_caches

  name          = each.key
  provider_name = each.value.type
  endpoint_url  = each.value.url
  access_id     = each.key == "dhi" ? data.vault_kv_secret_v2.dhi.data["username"] : ""
  access_secret = each.key == "dhi" ? data.vault_kv_secret_v2.dhi.data["token"] : ""
}

resource "harbor_project" "proxy" {
  for_each = local.proxy_caches

  name                   = each.value.project
  registry_id            = harbor_registry.proxy[each.key].registry_id
  public                 = true
  vulnerability_scanning = false
}

# Sigstore bundles arrive as OCI referrers (ADR 0001), so cosign content trust is not enforced.
resource "harbor_project" "governed" {
  for_each = local.governed_projects

  name                   = each.key
  public                 = true
  vulnerability_scanning = true
  deployment_security    = "critical"
}

resource "harbor_replication" "governed" {
  for_each = local.governed_projects

  name                   = "${each.key}-from-ghcr"
  description            = "Pull ${each.value.ghcr_filter} from GHCR into Harbor project ${each.key}"
  action                 = "pull"
  registry_id            = harbor_registry.proxy["ghcr"].registry_id
  dest_namespace         = harbor_project.governed[each.key].name
  dest_namespace_replace = -1
  schedule               = local.replication_cron
  override               = true
  enabled                = true
  deletion               = false

  filters {
    name = each.value.ghcr_filter
  }
}

resource "harbor_replication" "runtime_demo" {
  name                   = "apps-demo-from-ghcr"
  description            = "Pull ${local.runtime_demo_filter} from GHCR into Harbor project apps"
  action                 = "pull"
  registry_id            = harbor_registry.proxy["ghcr"].registry_id
  dest_namespace         = harbor_project.governed["apps"].name
  dest_namespace_replace = -1
  schedule               = local.replication_cron
  override               = true
  enabled                = true
  deletion               = false

  filters {
    name = local.runtime_demo_filter
  }
}

resource "harbor_replication" "demo_fixtures" {
  name                   = "apps-demo-fixtures-from-ghcr"
  description            = "Pull ${local.demo_fixtures_filter} from GHCR into Harbor project apps"
  action                 = "pull"
  registry_id            = harbor_registry.proxy["ghcr"].registry_id
  dest_namespace         = harbor_project.governed["apps"].name
  dest_namespace_replace = -1
  schedule               = local.replication_cron
  override               = true
  enabled                = true
  deletion               = false

  filters {
    name = local.demo_fixtures_filter
  }
}

# Harbor prefixes system robot names with "robot$". The secret is written only (secret_wo);
# bump secret_wo_version after rotating it in OpenBao.
resource "harbor_robot_account" "dt_bridge" {
  name              = "dt-bridge"
  description       = "Read-only access of dt-bridge to the governed projects"
  level             = "system"
  duration          = -1
  disable           = false
  secret_wo         = ephemeral.vault_kv_secret_v2.robot_dt_bridge.data["password"]
  secret_wo_version = 1

  dynamic "permissions" {
    for_each = harbor_project.governed
    content {
      kind      = "project"
      namespace = permissions.value.name

      dynamic "access" {
        for_each = local.dt_bridge_access
        content {
          resource = access.value.resource
          action   = access.value.action
        }
      }
    }
  }
}

# Tags are immutable except the sha256-* referrers fallback tags, which later attestations update.
resource "harbor_immutable_tag_rule" "governed" {
  for_each = local.governed_projects

  project_id    = harbor_project.governed[each.key].id
  repo_matching = "**"
  tag_excluding = "sha256-*"
}

# Tags of each pinned digest, read anonymously from the public governed projects. Retention selects
# artifacts by tag only. A digest not replicated yet has no tag here: it is the newest artifact of its
# repository, kept by the most-recent rule until `task harbor:configure` runs after its replication.
data "http" "pinned_image" {
  for_each = local.pinned_images

  url             = "${local.harbor_url}/api/v2.0/projects/${each.value.project}/repositories/${replace(each.value.repository, "/", "%252F")}/artifacts/${each.value.digest}?with_tag=true"
  request_headers = { Accept = "application/json" }

  lifecycle {
    postcondition {
      condition     = contains([200, 404], self.status_code)
      error_message = "Harbor answered ${self.status_code} for ${each.key}"
    }
  }
}

locals {
  # project => repository => sorted tags of its pinned digests.
  retained_tags = {
    for project in keys(local.governed_projects) : project => {
      for repository in distinct([for image in values(local.pinned_images) : image.repository if image.project == project]) :
      repository => sort(distinct(flatten([
        for key, image in local.pinned_images : try([for tag in jsondecode(data.http.pinned_image[key].response_body).tags : tag.name], [])
        if image.project == project && image.repository == repository && data.http.pinned_image[key].status_code == 200
      ])))
    }
  }
}

# Keeps the most recently pushed artifacts of each repository, every referrers fallback tag and every
# digest pinned by images/catalog.yaml or the workload manifests.
resource "harbor_retention_policy" "governed" {
  for_each = local.governed_projects

  scope    = harbor_project.governed[each.key].id
  schedule = local.retention_cron

  rule {
    most_recently_pushed = 10
    repo_matching        = "**"
    tag_matching         = "**"
  }

  rule {
    always_retain = true
    repo_matching = "**"
    tag_matching  = "sha256-*"
  }

  dynamic "rule" {
    for_each = { for repository, tags in local.retained_tags[each.key] : repository => tags if length(tags) > 0 }
    content {
      always_retain      = true
      repo_matching      = rule.key
      tag_matching       = length(rule.value) == 1 ? rule.value[0] : "{${join(",", rule.value)}}"
      untagged_artifacts = false
    }
  }
}

resource "harbor_project_webhook" "dt_bridge" {
  for_each = local.governed_projects

  name             = "dt-bridge"
  description      = "Artifact events for dt-bridge"
  project_id       = harbor_project.governed[each.key].id
  address          = local.webhook_address
  auth_header      = "Bearer ${data.vault_kv_secret_v2.webhook_dt_bridge.data["token"]}"
  notify_type      = "http"
  events_types     = ["PUSH_ARTIFACT", "REPLICATION"]
  skip_cert_verify = false
}
