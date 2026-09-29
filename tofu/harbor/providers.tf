# OpenBao (VAULT_ADDR, VAULT_TOKEN) is reached with a short-lived `harbor-tofu` token whose policy
# cannot create child tokens. The Harbor admin password is ephemeral: it never lands in state.
provider "vault" {
  skip_child_token = true
}

ephemeral "vault_kv_secret_v2" "harbor_admin" {
  mount = "secret"
  name  = "platform/harbor-admin"
}

provider "harbor" {
  url      = local.harbor_url
  username = "admin"
  password = ephemeral.vault_kv_secret_v2.harbor_admin.data["password"]
}
