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
output "helm_values" {
  description = "Chart values that must match this module's output. Feed directly to helm_release."
  value = {
    "azure.clientId"        = azurerm_user_assigned_identity.operator.client_id
    "azure.tenantId"        = azurerm_user_assigned_identity.operator.tenant_id
    "serviceAccount.name"   = var.service_account_name
    "serviceAccount.create" = "true"
  }
}

output "role_assigned" {
  description = "Which role the operator identity was granted on the vault."
  value       = var.use_import_only_role ? azurerm_role_definition.importer[0].name : "Key Vault Certificates Officer"
}
