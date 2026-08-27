# Azure-side wiring for keyvault-certoperator.
#
# Scope is deliberately narrow: this module creates the operator's identity and
# the one role assignment it needs, and nothing else. It does not create the
# Key Vault, touch the vault's network rules, or install the chart -- all three
# are usually owned by someone else, and a module that fights the vault's owner
# over network_acls is worse than no module. See examples/aks for the whole
# picture assembled from parts.

resource "azurerm_user_assigned_identity" "operator" {
  name                = var.identity_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

# Binds the identity to one ServiceAccount in one namespace of one cluster.
# The subject is matched as a literal string: if the ServiceAccount is renamed,
# or the chart is installed under a different release name, this silently stops
# matching and every Key Vault call fails token exchange.
resource "azurerm_federated_identity_credential" "operator" {
  name                      = "${var.identity_name}-${var.namespace}"
  user_assigned_identity_id = azurerm_user_assigned_identity.operator.id
  issuer                    = var.oidc_issuer_url
  subject                   = "system:serviceaccount:${var.namespace}:${var.service_account_name}"

  # Fixed across every Azure cloud, including sovereign ones. Not a placeholder.
  audience = ["api://AzureADTokenExchange"]
}

# Key Vault Certificates Officer is the only built-in role that carries
# certificates/import, but it also grants delete and purge. This custom role is
# the actual set of actions the operator performs: import, and the read it does
# first so it can skip importing when nothing changed.
#
# That read matters for more than tidiness. ImportCertificate is not
# idempotent -- every call mints a permanent version, versions cannot be
# deleted, and past 500 the vault can no longer be backed up.
resource "azurerm_role_definition" "importer" {
  count = var.use_import_only_role ? 1 : 0

  name        = "Key Vault Certificate Importer (${var.identity_name})"
  scope       = var.key_vault_id
  description = "Import certificates into Key Vault and read their metadata. No delete, no purge, no access to secret values."

  permissions {
    actions = []
    data_actions = [
      "Microsoft.KeyVault/vaults/certificates/import/action",
      "Microsoft.KeyVault/vaults/certificates/read",
    ]
    not_actions      = []
    not_data_actions = []
  }

  assignable_scopes = [var.key_vault_id]
}

resource "azurerm_role_assignment" "operator" {
  scope        = var.key_vault_id
  principal_id = azurerm_user_assigned_identity.operator.principal_id
  # A freshly created managed identity may not have replicated through Entra
  # yet. Without this the apply fails with PrincipalNotFound, and a second
  # apply "fixes" it -- a confusing first experience for something that is not
  # actually broken. Valid only because this principal really is a service
  # principal; it fails for other principal types.
  skip_service_principal_aad_check = true

  role_definition_name = var.use_import_only_role ? null : "Key Vault Certificates Officer"
  role_definition_id   = var.use_import_only_role ? azurerm_role_definition.importer[0].role_definition_resource_id : null
}

# Application Gateway reads the certificate through /secrets/, not
# /certificates/, so Secrets User is its true minimum -- Certificates User does
# not work, and Secrets Officer is more than it needs.
resource "azurerm_role_assignment" "application_gateway" {
  count = var.application_gateway_principal_id == null ? 0 : 1

  scope                            = var.key_vault_id
  principal_id                     = var.application_gateway_principal_id
  skip_service_principal_aad_check = true
  role_definition_name             = "Key Vault Secrets User"
}
