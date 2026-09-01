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
    Resource ID of an existing Key Vault. The grant is scoped to this vault and
    nothing wider -- never to the resource group or subscription.

    Either permission model works; say which one the vault uses with
    vault_authorization. Getting that wrong is the failure this module exists to
    prevent: a role assignment on an access-policy vault applies cleanly, shows
    up in the portal, and grants nothing at all.
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

    Ignored when vault_authorization is "access-policy": roles of either kind
    are ignored by such a vault, and the access policy it gets instead is
    already exactly Get and Import.
  EOT
  type        = bool
  default     = false
}

variable "vault_authorization" {
  description = <<-EOT
    Which permission model the vault in key_vault_id uses, and therefore which
    kind of grant the operator identity gets:

      rbac          -- a role assignment (the default; enable_rbac_authorization
                       = true on the vault)
      access-policy -- a Key Vault access policy granting certificate Get and
                       Import (the legacy model, still the default for a vault
                       created without enable_rbac_authorization)

    The two are not interchangeable and neither is ignored quietly by Azure: a
    role assignment on an access-policy vault is accepted and does nothing, and
    an access policy on an RBAC vault is likewise inert. Both cases surface only
    later, as a 403 on import that names no cause -- so this module checks the
    value against the vault it was pointed at and fails the plan on a mismatch.

    Get and Import are the operator's entire Key Vault surface. It never lists
    (it reads one certificate by name) and never updates (the chain digest it
    compares against travels inside the import request), so nothing wider is
    warranted.
  EOT
  type        = string
  default     = "rbac"

  validation {
    condition     = contains(["rbac", "access-policy"], var.vault_authorization)
    error_message = "vault_authorization must be \"rbac\" or \"access-policy\"."
  }
}

variable "application_gateway_principal_id" {
  description = <<-EOT
    Principal (object) ID of the identity Application Gateway uses to read
    certificates. When set, it is granted read access to the vault's secrets --
    Key Vault Secrets User under RBAC, secret Get as an access policy --
    following vault_authorization like the operator's own grant.

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
