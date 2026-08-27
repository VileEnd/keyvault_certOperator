# Terraform module: Azure wiring for keyvault-certoperator

Creates the operator's managed identity, federates it to its Kubernetes
ServiceAccount, and grants it the one Key Vault role it needs — scoped to the
vault, never wider.

```hcl
module "certoperator_identity" {
  source = "github.com/VileEnd/keyvault_certOperator//terraform?ref=v0.1.1"

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
  version    = "0.1.1"

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

The `?ref=v0.1.1` above is load-bearing. Without it the source tracks `main`, so
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

The vault must use RBAC, not the legacy access-policy model:

```hcl
resource "azurerm_key_vault" "this" {
  enable_rbac_authorization = true
}
```

With access policies these role assignments have no effect at all, and every
import fails with a 403 that does not explain why.

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
| `use_import_only_role` | bool | `false` | Custom import-only role instead of Certificates Officer. |
| `application_gateway_principal_id` | string | `null` | Granted Key Vault Secrets User when set. |
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
| `role_assigned` | Which role was granted on the vault. |

## Which role

`use_import_only_role = false` (default) grants **Key Vault Certificates
Officer**. It is the only built-in role carrying `certificates/import`, but it
also grants delete and purge — which this operator never uses, and which are
irreversible on a vault with purge protection off.

`use_import_only_role = true` creates a custom role with exactly two data
actions: `certificates/import/action` and `certificates/read`. That read is not
decoration — the operator checks the stored certificate before importing,
because `ImportCertificate` is not idempotent: every call mints a permanent
version, versions can never be deleted, and past 500 the vault can no longer be
backed up.

The custom role needs permission to create role definitions, which not every
pipeline identity has. That is the only reason it is not the default.

## Both sides of the scoping

The role assignment bounds what the identity *can* write to. It does not bound
what a cluster user may *ask* for -- `spec.keyVault` is chosen per-resource.

`helm_values` therefore also carries `azure.allowedVaults[0]`, set to the same
vault the role assignment was scoped to. The Azure grant and the operator's own
bound come from one source and cannot drift apart, and a resource naming any
other vault fails immediately as a configuration error instead of as a 403 the
operator would keep retrying.

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
