# End-to-end wiring for an existing AKS cluster and Key Vault.
#
# Read the ordering note at the bottom before running this against a gateway
# that is already serving traffic.

terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0"
    }
    helm = {
      source = "hashicorp/helm"
      # Pinned to 2.x on purpose. Provider 3.0 turned `set` from a block into
      # an attribute and `kubernetes` likewise, so the dynamic block below and
      # the provider config above both stop parsing under >= 3.
      version = "~> 2.12"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_kubernetes_cluster" "this" {
  name                = var.cluster_name
  resource_group_name = var.resource_group_name
}

data "azurerm_key_vault" "this" {
  name                = var.key_vault_name
  resource_group_name = var.key_vault_resource_group_name
}

# Certificate-based admin credentials. A cluster with Entra integration or
# local accounts disabled will not return these -- use exec-based auth against
# kubelogin there instead.
provider "helm" {
  kubernetes {
    host                   = data.azurerm_kubernetes_cluster.this.kube_config[0].host
    client_certificate     = base64decode(data.azurerm_kubernetes_cluster.this.kube_config[0].client_certificate)
    client_key             = base64decode(data.azurerm_kubernetes_cluster.this.kube_config[0].client_key)
    cluster_ca_certificate = base64decode(data.azurerm_kubernetes_cluster.this.kube_config[0].cluster_ca_certificate)
  }
}

module "certoperator_identity" {
  source = "../.."

  resource_group_name = var.resource_group_name
  location            = var.location
  key_vault_id        = data.azurerm_key_vault.this.id

  # Empty unless the cluster has oidc_issuer_enabled = true. The module's
  # variable validation catches that rather than letting you apply a federated
  # credential that can never match.
  oidc_issuer_url = data.azurerm_kubernetes_cluster.this.oidc_issuer_url

  # The gateway's own identity, granted only Key Vault Secrets User. Leave null
  # if the gateway is managed elsewhere.
  application_gateway_principal_id = var.application_gateway_principal_id
}

# The ServiceAccount name comes from the module, so the name the chart creates
# and the name the federated credential expects cannot drift apart. That
# mismatch is the single most common way this setup fails, and it surfaces as
# AADSTS70021 at token exchange -- which never mentions the name.
resource "helm_release" "certoperator" {
  name             = "keyvault-certoperator"
  namespace        = module.certoperator_identity.namespace
  create_namespace = true

  repository = var.chart_repository
  chart      = var.chart_name
  version    = var.chart_version

  dynamic "set" {
    for_each = module.certoperator_identity.helm_values
    content {
      name  = set.key
      value = set.value
    }
  }
}

# A policy is a Kubernetes object, so it is applied with kubectl or your GitOps
# tool rather than Terraform. See config/samples for the Gateway API variant.

# ---------------------------------------------------------------------------
# Application Gateway listeners
# ---------------------------------------------------------------------------
#
# Ordering matters and Terraform cannot express it for you. A listener that
# references a Key Vault certificate fails to create while that certificate
# does not exist yet, and the operator only creates it after cert-manager has
# issued -- which for a DNS-01 wildcard takes minutes.
#
# So run this in two passes:
#
#   1. terraform apply           -- identity, RBAC, the operator
#   2. apply the policy, wait for status.secretIdentifier to be populated
#   3. terraform apply           -- with the ssl_certificate block below
#
# The URI must be the versionless one the operator reports in
# status.secretIdentifier. A versioned URI permanently disables Application
# Gateway's four-hourly automatic rotation, which is the entire reason the
# certificate lives in Key Vault rather than being uploaded to the gateway.
#
#   ssl_certificate {
#     name                = "wildcard-x-com"
#     key_vault_secret_id = "${data.azurerm_key_vault.this.vault_uri}secrets/wildcard-x-com"
#   }
#
# The gateway also needs the identity granted above attached to it:
#
#   identity {
#     type         = "UserAssigned"
#     identity_ids = [var.application_gateway_identity_id]
#   }
