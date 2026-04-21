# ──────────────────────────────────────
# Dock Shield - DigitalOcean Infrastructure
# ──────────────────────────────────────

terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

variable "do_token" {
  description = "DigitalOcean API Token"
  sensitive   = true
}

variable "region" {
  default = "blr1" # Bangalore
}

provider "digitalocean" {
  token = var.do_token
}

# Query currently supported DOKS versions so cluster creation doesn't fail on deprecated slugs.
data "digitalocean_kubernetes_versions" "supported" {}

# ─── Kubernetes Cluster ───
resource "digitalocean_kubernetes_cluster" "dock_shield" {
  name    = "dock-shield-cluster"
  region  = var.region
  version = data.digitalocean_kubernetes_versions.supported.latest_version

  node_pool {
    name       = "dock-shield-pool"
    size       = "s-2vcpu-2gb"
    node_count = 1
    auto_scale = false
  }
}

# ─── Outputs ───
output "cluster_endpoint" {
  value = digitalocean_kubernetes_cluster.dock_shield.endpoint
}

output "cluster_id" {
  value = digitalocean_kubernetes_cluster.dock_shield.id
}

output "kubeconfig" {
  value     = digitalocean_kubernetes_cluster.dock_shield.kube_config[0].raw_config
  sensitive = true
}
