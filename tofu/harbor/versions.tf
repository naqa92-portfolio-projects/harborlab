# State stays local and encrypted by an OpenBao Transit data key; BAO_ADDR and BAO_TOKEN come
# from scripts/harbor-tofu.sh. A plaintext state is refused (enforced).
terraform {
  required_version = "~> 1.12.0"

  required_providers {
    harbor = {
      source  = "goharbor/harbor"
      version = "3.12.5"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "5.12.0"
    }
  }

  backend "local" {
    path = "terraform.tfstate"
  }

  encryption {
    key_provider "openbao" "state" {
      key_name = "harbor-tofu-state"
    }

    method "aes_gcm" "state" {
      keys = key_provider.openbao.state
    }

    state {
      method   = method.aes_gcm.state
      enforced = true
    }
  }
}
