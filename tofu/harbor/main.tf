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

  # Governed projects, pulled from GHCR. No tag filter: the cosign referrers fallback tags
  # (sha256-*) are replicated with the images.
  governed_projects = {
    golden = { ghcr_filter = "naqa92-portfolio-projects/harborlab/golden/**" }
    apps   = { ghcr_filter = "naqa92-portfolio-projects/harborlab/apps/**" }
  }

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

# The dhi.io credential has no write-only variant: it is the one secret the encrypted state holds.
data "vault_kv_secret_v2" "dhi" {
  mount = "secret"
  name  = "platform/dhi"
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

# Keeps the most recently pushed artifacts of each repository and every referrers fallback tag.
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
}

resource "harbor_project_webhook" "dt_bridge" {
  for_each = local.governed_projects

  name             = "dt-bridge"
  description      = "Artifact events for dt-bridge"
  project_id       = harbor_project.governed[each.key].id
  address          = local.webhook_address
  notify_type      = "http"
  events_types     = ["PUSH_ARTIFACT", "REPLICATION"]
  skip_cert_verify = false
  payload_format   = "Default"
}
