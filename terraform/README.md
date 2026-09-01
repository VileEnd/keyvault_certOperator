# Terraform module: Azure wiring for keyvault-certoperator

Creates the operator's managed identity, federates it to its Kubernetes
ServiceAccount, and gives it the one Key Vault grant it needs — scoped to the
vault, never wider — as a role assignment or as an access policy, whichever the
vault's permission model actually honours.

```hcl
module "certoperator_identity" {
  source = "github.com/VileEnd/keyvault_certOperator//terraform?ref=v0.2.0"

  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  key_vault_id        = azurerm_key_vault.this.id
  oidc_issuer_url     = azurerm_kubernetes_cluster.this.oidc_issuer_url
}
```

Then install the chart with the values the module hands back:

```hcl
resource "helm_release" "certoperator" {
  name             = "keyvault-certoperator"
  namespace        = module.certoperator_identity.namespace
  create_namespace = true

  repository = "oci://ghcr.io/vileend/charts"
  chart      = "keyvault-certoperator"
  version    = "0.2.0"

  dynamic "set" {
    for_each = module.certoperator_identity.helm_values
    content {
      name  = set.key
      value = set.value
    }
  }
}
```

Wiring `helm_values` through rather than setting `azure.clientId` by hand is the
point: it keeps the ServiceAccount name the chart creates identical to the one
the federated credential expects. See **The failure everyone hits** below.

A complete example against an existing cluster and vault is in
[`examples/aks`](examples/aks).

## Pinning

The `?ref=v0.2.0` above is load-bearing. Without it the source tracks `main`, so
a `terraform apply` months from now can pick up whatever merged in between.

What the tag promises is a reproducible artifact, not a stable interface. The
API is `v1alpha1` and the operator has not yet run against a real Key Vault, so
variable names may still move. Pin it, and read the release notes before moving.

## What it deliberately does not do

- **Create the Key Vault.** Vaults usually belong to a different team and have
  their own lifecycle, retention and purge-protection settings. Pass an existing
  one.
- **Manage the vault's network rules.** A module that fights the vault's owner
  over `network_acls` is worse than no module. The rules you need are described
  in [docs/azure-setup.md](../docs/azure-setup.md#networking).
- **Install the chart.** That is one `helm_release` in your own configuration,
  shown above and in the example, and it keeps the Kubernetes provider out of
  this module.
- **Write Application Gateway configuration.** The operator holds no ARM
  permissions by design and neither does this module. It emits the listener
  facts; you apply them. The ordering this requires is described in the example.

## Prerequisites

The cluster must have both enabled — neither is on by default:

```hcl
resource "azurerm_kubernetes_cluster" "this" {
  oidc_issuer_enabled       = true
  workload_identity_enabled = true
}
```

The vault may use either permission model — but the module has to be told
which, because a grant of the wrong kind applies cleanly and then does nothing:

```hcl
# Azure RBAC (the default here): the operator gets a role assignment.
module "certoperator_identity" {
  # ...
  vault_authorization = "rbac"
}

# Access policies: the operator gets certificate Get and Import instead.
module "certoperator_identity" {
  # ...
  vault_authorization = "access-policy"
}
```

The operator itself does not care. Its entire Azure surface is two Key Vault
data-plane calls — `GetCertificate` and `ImportCertificate` — and it holds no
resource-manager SDK at all, so it never reads `enableRbacAuthorization` and
behaves identically under either model. Only the *grant* differs, and Azure
accepts the wrong one silently: a role assignment on an access-policy vault
appears in the portal, reports success, and authorizes nothing. The first sign
is a 403 on import, which the operator now reports as `VaultAccessDenied`
rather than backing off against it forever. It still re-checks it every couple
of minutes, because a grant of the *right* kind answers the same 403 for as long
as it takes to propagate.

That is what the module's preconditions exist to catch. Both grants are checked
against the vault's own `rbac_authorization_enabled` before anything is created,
so a mismatch fails the plan with a sentence instead of shipping an inert grant.

## Upgrading a module that predates `vault_authorization`

The operator's role assignment is now conditional, so it moved from
`azurerm_role_assignment.operator` to `azurerm_role_assignment.operator[0]`.
State that once and the plan is empty again:

```console
$ terraform state mv 'module.certoperator_identity.azurerm_role_assignment.operator' \
    'module.certoperator_identity.azurerm_role_assignment.operator[0]'
```

## Inputs

| Name | Type | Default | Description |
|---|---|---|---|
| `resource_group_name` | string | — | Resource group for the managed identity. |
| `location` | string | — | Region for the managed identity. |
| `key_vault_id` | string | — | Existing vault's resource ID. Role assignment is scoped here. |
| `oidc_issuer_url` | string | — | `azurerm_kubernetes_cluster.this.oidc_issuer_url`. |
| `identity_name` | string | `keyvault-certoperator` | Managed identity name. |
| `namespace` | string | `keyvault-certoperator-system` | Namespace the operator runs in. |
| `service_account_name` | string | `keyvault-certoperator` | Must match the SA that actually exists. |
| `use_import_only_role` | bool | `false` | Custom import-only role instead of Certificates Officer. Ignored under access policies. |
| `vault_authorization` | string | `rbac` | `rbac` or `access-policy`. Must match the vault, and is checked against it. |
| `application_gateway_principal_id` | string | `null` | Granted read access to the vault's secrets when set. |
| `tags` | map(string) | `{}` | Tags for created resources. |

## Outputs

| Name | Description |
|---|---|
| `client_id` | The chart's `azure.clientId`. |
| `tenant_id` | The chart's `azure.tenantId`. |
| `principal_id` | Identity's principal (object) ID. |
| `identity_id` | Identity's resource ID. |
| `namespace` / `service_account_name` | What the credential is federated to. |
| `federated_subject` | The literal subject string, for debugging. |
| `key_vault_uri` | Base URI of the granted vault; also the operator's allowlist entry. |
| `key_vault_secret_uri_prefix` | Prefix for versionless listener URIs. |
| `helm_values` | Map to feed straight into `helm_release`. |
| `role_assigned` | What was granted on the vault: a role name, or the access policy's permissions. |
| `vault_authorization` | The permission model the grant was made under. |

## Which role, or which access policy

Under `vault_authorization = "access-policy"` there is no role: the identity
gets a Key Vault access policy carrying certificate **Get** and **Import**, and
`use_import_only_role` is ignored because that policy is already exactly the two
permissions the operator uses. It never lists — it reads one certificate by name
— and never updates, because the chain digest it compares against travels inside
the import request rather than as a separate tag write.

One caveat: `azurerm_key_vault_access_policy` adds an entry to a vault this
module does not own, and it cannot be combined with inline `access_policy`
blocks on the vault's own resource — the two representations overwrite each
other on every apply. Where the vault is declared that way, add the operator's
entry alongside the vault's other ones, using `principal_id` from this module;
there is no mode here for a grant made elsewhere.

Under RBAC, `use_import_only_role = false` (default) grants **Key Vault
Certificates Officer**. It is the only built-in role carrying
`certificates/import`, but it also grants delete and purge — which this operator
never uses, and which are irreversible on a vault with purge protection off.

`use_import_only_role = true` creates a custom role with exactly two data
actions: `certificates/import/action` and `certificates/read`. That read is not
decoration — the operator checks the stored certificate before importing,
because `ImportCertificate` is not idempotent: every call mints a permanent
version, versions can never be deleted, and past 500 the vault can no longer be
backed up.

The custom role needs permission to create role definitions, which not every
pipeline identity has. That is the only reason it is not the default.

## Both sides of the scoping

The grant bounds what the identity *can* write to. It does not bound what a
cluster user may *ask* for -- `spec.keyVault` is chosen per-resource.

`helm_values` therefore also carries `azure.allowedVaults[0]`, set to the same
vault the grant was scoped to. The Azure grant and the operator's own bound come
from one source and cannot drift apart, and a resource naming any other vault is
refused before the operator connects to that host at all — reporting the
allowlist it violated, rather than the access denial the vault would have
answered with, which names a permission nobody intended to give it.

## The failure everyone hits

The federated credential matches its subject as a **literal string**:

```
system:serviceaccount:<namespace>:<service-account-name>
```

The two install paths do not produce the same name:

| Install | ServiceAccount |
|---|---|
| Helm, release named `keyvault-certoperator` | `keyvault-certoperator` |
| kustomize (`config/`) | `keyvault-certoperator-controller-manager` |

If they disagree, nothing warns you. The operator starts, reports ready, and
every Key Vault call fails token exchange with **AADSTS70021** (or
**AADSTS700213**, which at least names the subject as the mismatch). Neither
mentions that a ServiceAccount name is wrong.

Check the actual name against `federated_subject`:

```console
$ kubectl get sa -n keyvault-certoperator-system
$ terraform output federated_subject
```

## After a fresh apply, expect a few failures

Federated identity credentials take time to propagate across the region.
Microsoft documents that a token request made minutes after creating one can
fail with AADSTS70021 while caches still hold old data. The operator retries
with backoff, so this resolves itself — do not go hunting for a
misconfiguration in the first few minutes of a brand-new identity.
