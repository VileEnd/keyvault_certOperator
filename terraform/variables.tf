variable "resource_group_name" {
  description = "Resource group to create the operator's managed identity in."
  type        = string
}

variable "location" {
  description = "Azure region for the managed identity."
  type        = string
}

variable "key_vault_id" {
  description = <<-EOT
    Resource ID of an existing Key Vault. The role assignment is scoped to this
    vault and nothing wider -- never to the resource group or subscription.

    The vault must have RBAC authorization enabled (enable_rbac_authorization =
    true). With the legacy access-policy model these role assignments have no
    effect and every import fails with a 403 that does not explain why.
  EOT
  type        = string

  validation {
    condition     = can(regex("/providers/Microsoft.KeyVault/vaults/", var.key_vault_id))
    error_message = "key_vault_id must be a full Key Vault resource ID, not a name or URI."
  }
}

variable "oidc_issuer_url" {
  description = <<-EOT
    The AKS cluster's OIDC issuer URL, from
    azurerm_kubernetes_cluster.this.oidc_issuer_url.

    The cluster needs oidc_issuer_enabled = true and workload_identity_enabled
    = true. Neither is on by default.
  EOT
  type        = string

  validation {
    condition     = startswith(var.oidc_issuer_url, "https://")
    error_message = "oidc_issuer_url must be the https issuer URL. An empty value usually means oidc_issuer_enabled is false on the cluster."
  }
}

variable "identity_name" {
  description = "Name of the user-assigned managed identity created for the operator."
  type        = string
  default     = "keyvault-certoperator"
}

variable "namespace" {
  description = "Kubernetes namespace the operator runs in."
  type        = string
  default     = "keyvault-certoperator-system"
}

variable "service_account_name" {
  description = <<-EOT
    Name of the operator's Kubernetes ServiceAccount. This has to match what is
    actually created in the cluster, exactly -- the federated credential's
    subject is a literal string and a mismatch fails at token exchange with
    AADSTS70021, which does not tell you the name is wrong.

    The default matches the Helm chart when the release is named
    keyvault-certoperator. The kustomize manifests under config/ create
    "keyvault-certoperator-controller-manager" instead. Pin it either way with
    the service_account_name output, which is wired into helm_values.
  EOT
  type        = string
  default     = "keyvault-certoperator"
}

variable "use_import_only_role" {
  description = <<-EOT
    Create and assign a custom role carrying only certificates/import, instead
    of the built-in Key Vault Certificates Officer.

    Officer is the only built-in role that includes import, but it also grants
    delete and purge, which this operator never uses. The custom role is the
    true least privilege; it needs permission to create role definitions at the
    subscription scope, which not every pipeline identity has.
  EOT
  type        = bool
  default     = false
}

variable "application_gateway_principal_id" {
  description = <<-EOT
    Principal (object) ID of the identity Application Gateway uses to read
    certificates. When set, it is granted Key Vault Secrets User on the vault.

    This must be a different identity from the operator's. The gateway reads
    /secrets/, the operator writes /certificates/; sharing one identity gives
    each of them permissions it has no use for.
  EOT
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to resources this module creates."
  type        = map(string)
  default     = {}
}
