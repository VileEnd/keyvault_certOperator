output "client_id" {
  description = "Client ID annotated onto the operator's ServiceAccount."
  value       = module.certoperator_identity.client_id
}

output "federated_subject" {
  description = "The literal subject the federated credential matches. Compare with the running pod's ServiceAccount if token exchange fails."
  value       = module.certoperator_identity.federated_subject
}

output "key_vault_secret_uri_prefix" {
  description = "Prefix for the versionless secret URIs to paste into Application Gateway listeners."
  value       = module.certoperator_identity.key_vault_secret_uri_prefix
}
