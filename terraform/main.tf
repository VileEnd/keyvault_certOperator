# Azure-side wiring for keyvault-certoperator.
#
# Scope is deliberately narrow: this module creates the operator's identity and
# the one role assignment it needs, and nothing else. It does not create the
# Key Vault, touch the vault's network rules, or install the chart -- all three
# are usually owned by someone else, and a module that fights the vault's owner
# over network_acls is worse than no module. See examples/aks for the whole
# picture assembled from parts.

# Reading the vault back gives us its URI for the allowlist, its tenant for an
# access policy, and the permission model the grants below are checked against.
# It also fails the plan early with a clear message if key_vault_id points at
# something that is not a vault or is not visible to this identity.
data "azurerm_key_vault" "target" {
  name                = reverse(split("/", var.key_vault_id))[0]
  resource_group_name = split("/", var.key_vault_id)[4]
}

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
  # Off under access policies as well: a role definition nobody can be assigned
  # is just a subscription-scoped object left behind by a plan that had no use
  # for it.
  count = var.vault_authorization == "rbac" && var.use_import_only_role ? 1 : 0

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
  count = var.vault_authorization == "rbac" ? 1 : 0

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

  lifecycle {
    # The vault answers a role assignment it does not honour with silence, so
    # this is the only place the mistake can still be cheap. Without the check
    # the apply succeeds, the portal shows the assignment, and the first sign of
    # trouble is a 403 on import hours later.
    precondition {
      condition     = data.azurerm_key_vault.target.rbac_authorization_enabled
      error_message = "This vault uses access policies, where role assignments are ignored. Set vault_authorization = \"access-policy\"."
    }
  }
}

# The access-policy half of the same grant. Certificates Get and Import, which
# is the operator's whole Key Vault surface: it reads one certificate by name
# before deciding whether to import, so it never lists, and the chain digest it
# compares against is a tag inside the import request rather than an update.
#
# This adds one entry to a vault someone else owns. A vault whose own resource
# declares inline access_policy blocks cannot be extended this way -- the two
# representations overwrite each other on every apply -- so such a vault needs
# the entry added where the vault itself is defined.
resource "azurerm_key_vault_access_policy" "operator" {
  count = var.vault_authorization == "access-policy" ? 1 : 0

  key_vault_id = var.key_vault_id
  # The vault's tenant, not the identity's: an access policy entry is only ever
  # evaluated in the tenant the vault belongs to.
  tenant_id = data.azurerm_key_vault.target.tenant_id
  object_id = azurerm_user_assigned_identity.operator.principal_id

  certificate_permissions = ["Get", "Import"]

  lifecycle {
    precondition {
      condition     = !data.azurerm_key_vault.target.rbac_authorization_enabled
      error_message = "This vault uses Azure RBAC, where access policies are ignored. Leave vault_authorization at its default, \"rbac\"."
    }
  }
}

# Application Gateway reads the certificate through /secrets/, not
# /certificates/, so Secrets User is its true minimum -- Certificates User does
# not work, and Secrets Officer is more than it needs. Azure's own
# troubleshooting guide names the access-policy equivalent as secret Get, and
# says outright that a policy carrying certificate permissions instead is the
# same failure.
resource "azurerm_role_assignment" "application_gateway" {
  count = var.application_gateway_principal_id != null && var.vault_authorization == "rbac" ? 1 : 0

  scope                            = var.key_vault_id
  principal_id                     = var.application_gateway_principal_id
  skip_service_principal_aad_check = true
  role_definition_name             = "Key Vault Secrets User"
}

resource "azurerm_key_vault_access_policy" "application_gateway" {
  count = var.application_gateway_principal_id != null && var.vault_authorization == "access-policy" ? 1 : 0

  key_vault_id = var.key_vault_id
  tenant_id    = data.azurerm_key_vault.target.tenant_id
  object_id    = var.application_gateway_principal_id

  secret_permissions = ["Get"]
}
