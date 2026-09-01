output "client_id" {
  description = "Client ID of the operator's managed identity. This is azure.clientId in the chart."
  value       = azurerm_user_assigned_identity.operator.client_id
}

output "principal_id" {
  description = "Principal (object) ID of the operator's managed identity."
  value       = azurerm_user_assigned_identity.operator.principal_id
}

output "tenant_id" {
  description = "Tenant ID the identity belongs to."
  value       = azurerm_user_assigned_identity.operator.tenant_id
}

output "identity_id" {
  description = "Resource ID of the operator's managed identity."
  value       = azurerm_user_assigned_identity.operator.id
}

output "service_account_name" {
  description = "The ServiceAccount name the federated credential is bound to. Install the chart with exactly this name."
  value       = var.service_account_name
}

output "namespace" {
  description = "The namespace the federated credential is bound to."
  value       = var.namespace
}

output "federated_subject" {
  description = "The literal subject the federated credential matches. Compare against the running pod's ServiceAccount when token exchange fails."
  value       = azurerm_federated_identity_credential.operator.subject
}

# Wired straight into helm_release.set so the ServiceAccount name cannot drift
# from the federated credential's subject. See examples/aks.
output "key_vault_uri" {
  description = "Base URI of the vault the identity was granted on. Also the operator's allowlist entry."
  value       = data.azurerm_key_vault.target.vault_uri
}

output "key_vault_secret_uri_prefix" {
  description = "Prefix for the versionless secret URIs to paste into Application Gateway listeners."
  value       = "${data.azurerm_key_vault.target.vault_uri}secrets/"
}

output "helm_values" {
  description = "Chart values that must match this module's output. Feed directly to helm_release."
  value = {
    "azure.clientId"        = azurerm_user_assigned_identity.operator.client_id
    "azure.tenantId"        = azurerm_user_assigned_identity.operator.tenant_id
    "serviceAccount.name"   = var.service_account_name
    "serviceAccount.create" = "true"
    # The vault the grant above was scoped to. Passing it through means the
    # Azure grant and the operator's own bound come from one source and cannot
    # disagree: a resource naming any other vault is refused before the operator
    # connects to it, and reports the allowlist it violated rather than the
    # access denial the vault would answer with.
    "azure.allowedVaults[0]" = data.azurerm_key_vault.target.vault_uri
  }
}

# Says what was actually granted, not what would have been under the other
# permission model -- the point of naming it at all is to be able to compare it
# against what the vault reports.
output "role_assigned" {
  description = "What the operator identity was granted on the vault: a role name under RBAC, or the access policy's permissions."
  # one() rather than [0]: under access policies the custom role is not created
  # at all, and an index into that empty list would fail the output rather than
  # report the access policy.
  value = (var.vault_authorization == "access-policy"
    ? "access policy: certificates Get, Import"
    : coalesce(one(azurerm_role_definition.importer[*].name), "Key Vault Certificates Officer")
  )
}

output "vault_authorization" {
  description = "The permission model the grants were made under. Compare against 'az keyvault show --query properties.enableRbacAuthorization'."
  value       = var.vault_authorization
}
