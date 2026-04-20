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

# ─── Kubernetes Cluster ───
resource "digitalocean_kubernetes_cluster" "dock_shield" {
  name    = "dock-shield-cluster"
  region  = var.region
  version = "1.29.1-do.0"

  node_pool {
    name       = "dock-shield-pool"
    size       = "s-2vcpu-4gb" # 4GB needed for Trivy scanning
    node_count = 2
    auto_scale = true
    min_nodes  = 1
    max_nodes  = 3
  }
}

# ─── Container Registry ───
resource "digitalocean_container_registry" "dock_shield" {
  name                   = "dock-shield-registry"
  subscription_tier_slug = "starter"
  region                 = var.region
}

# ─── Firewall ───
resource "digitalocean_firewall" "dock_shield" {
  name = "dock-shield-firewall"

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "4000"
    source_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0"]
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

output "registry_endpoint" {
  value = digitalocean_container_registry.dock_shield.endpoint
}
