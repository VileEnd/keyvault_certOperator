# Setting up the Azure side

Everything this operator needs from Azure, and the order to do it in. Three
paths are described — pick one:

- **[Terraform](#terraform)** — recommended if AKS is already managed as code.
- **[Azure CLI](#azure-cli)** — one script, good for trying it out.
- **[By hand](#what-the-pieces-actually-are)** — the underlying resources, if
  you are wiring this into something else.

All three produce the same four things:

1. A user-assigned managed identity for the operator.
2. A federated credential binding it to the operator's ServiceAccount.
3. A Key Vault role assignment for that identity, **scoped to the vault**.
4. A *separate* role assignment for Application Gateway's own identity.

## Prerequisites

| | Why |
|---|---|
| AKS with `oidc_issuer_enabled` **and** `workload_identity_enabled` | Neither is on by default. Without them there is no issuer to federate against. |
| A Key Vault with **RBAC authorization** enabled | Under the legacy access-policy model these role assignments do nothing and every import fails with an unexplained 403. |
| cert-manager, with a DNS-01 issuer | Wildcards cannot use HTTP-01. The operator creates `Certificate` resources; cert-manager does the issuing and owns renewal. |
| An Application Gateway you configure yourself | The operator holds no ARM permissions and never writes gateway config. |

## Terraform

```hcl
data "azurerm_kubernetes_cluster" "this" {
  name                = "my-aks"
  resource_group_name = "my-rg"
}

data "azurerm_key_vault" "this" {
  name                = "my-vault"
  resource_group_name = "my-rg"
}

module "certoperator_identity" {
  source = "github.com/VileEnd/keyvault_certOperator//terraform"

  resource_group_name = "my-rg"
  location            = "westeurope"
  key_vault_id        = data.azurerm_key_vault.this.id
  oidc_issuer_url     = data.azurerm_kubernetes_cluster.this.oidc_issuer_url

  # Optional: grant the gateway's identity Key Vault Secrets User at the same time.
  application_gateway_principal_id = azurerm_user_assigned_identity.appgw.principal_id
}

resource "helm_release" "certoperator" {
  name             = "keyvault-certoperator"
  namespace        = module.certoperator_identity.namespace
  create_namespace = true
  chart            = "./charts/keyvault-certoperator"

  dynamic "set" {
    for_each = module.certoperator_identity.helm_values
    content {
      name  = set.key
      value = set.value
    }
  }
}
```

Feeding `helm_values` through rather than setting `azure.clientId` by hand is
the whole point — it keeps the ServiceAccount name the chart creates identical
to the one the federated credential expects. That mismatch is the most common
way this setup fails; see [Troubleshooting](#troubleshooting).

Full module reference and a complete example: [`terraform/`](../terraform).

## Azure CLI

```console
$ export SUBSCRIPTION_ID=... RESOURCE_GROUP=... CLUSTER_NAME=... KEYVAULT_NAME=...
$ config/azure/setup.sh
```

It enables the OIDC issuer and workload identity on the cluster, creates the
identity, federates it, assigns the role, and prints the exact `helm upgrade`
command to run — including `--set serviceAccount.name=...`, which is pinned so
the name cannot drift from the federated subject.

Set `USE_CUSTOM_ROLE=1` for the import-only role instead of Certificates
Officer.

## What the pieces actually are

### The operator's identity

A user-assigned managed identity, federated to one ServiceAccount in one
namespace of one cluster. The subject is matched as a literal string:

```
system:serviceaccount:keyvault-certoperator-system:keyvault-certoperator
```

The audience is `api://AzureADTokenExchange` — fixed across every Azure cloud,
including sovereign ones. It is not a placeholder.

Workload identity also needs **both** of these on the workload, and the chart
sets both: the `azure.workload.identity/client-id` annotation on the
ServiceAccount, and the `azure.workload.identity/use: "true"` label on the pod.
Without the label the webhook skips the pod entirely and the operator fails at
its next restart rather than at deploy time.

### The operator's role

**Key Vault Certificates Officer**, scoped to the vault. It is the only built-in
role carrying `certificates/import`.

It also grants delete and purge, which this operator never uses. For true least
privilege use the import-only role
([`config/azure/keyvault-import-only-role.json`](../config/azure/keyvault-import-only-role.json),
or `use_import_only_role = true` in Terraform), which grants exactly:

- `Microsoft.KeyVault/vaults/certificates/import/action`
- `Microsoft.KeyVault/vaults/certificates/read`

The read is load-bearing. `ImportCertificate` is **not idempotent**: every call
mints a permanent version, versions can never be deleted, more than 500 breaks
vault backup, and each one is a candidate for Application Gateway's rotation
poll. The operator reads before writing so that a steady state performs no
writes at all.

Note what is *not* granted: `secrets/getSecret`. The operator never reads
certificate material back out of the vault, so it never needs the permission
that would expose private keys.

### Application Gateway's identity

A **different** identity, with a **narrower** role: **Key Vault Secrets User**.

The gateway reads the certificate through `/secrets/`, not `/certificates/`, so
Certificates User does not work and Secrets Officer is more than it needs. Never
share one identity between the operator and the gateway — the operator writes
certificates, the gateway only reads the secret behind one.

### Networking

If the vault has network ACLs, add the gateway's subnet **explicitly** — with
the `Microsoft.KeyVault` service endpoint — or use a private endpoint with the
`privatelink.vaultcore.azure.net` zone linked.

Do not rely on the trusted-services bypass. Microsoft's own documentation
disagrees with itself about whether Application Gateway qualifies, and the more
specific troubleshooting guidance says to allow the subnet. The AKS node subnet
needs its own path to the vault too; the operator's pod is definitely not a
trusted service.

## Order of operations

Terraform cannot express this dependency for you, because the middle step
happens inside the cluster:

1. **Apply the identity, RBAC and the operator.**
2. **Apply a `WildcardCertificatePolicy`** and wait for cert-manager to issue.
   For a DNS-01 wildcard this takes minutes, not seconds.
3. **Read the versionless URI** the operator reports:
   ```console
   $ kubectl get keyvaultcertificatesync -A \
       -o custom-columns=NAME:.metadata.name,URI:.status.secretIdentifier
   ```
4. **Point the listener at it**, and only now apply that part of your gateway
   configuration.

Doing step 4 first fails: a listener cannot reference a Key Vault certificate
that does not exist yet.

The URI must be the **versionless** one. A versioned URI permanently disables
the four-hourly automatic rotation, which is the entire reason for keeping the
certificate in Key Vault rather than uploading it to the gateway.

## Troubleshooting

### Every Key Vault call fails with AADSTS70021 or AADSTS700213

The federated subject does not match the ServiceAccount that exists. This is the
most common failure and nothing warns you about it — the operator starts fine
and reports ready.

The two install paths produce different names:

| Install | ServiceAccount |
|---|---|
| Helm, release named `keyvault-certoperator` | `keyvault-certoperator` |
| kustomize (`config/`) | `keyvault-certoperator-controller-manager` |

Compare them directly:

```console
$ kubectl get sa -n keyvault-certoperator-system
$ az identity federated-credential list \
    --identity-name keyvault-certoperator -g my-rg \
    --query "[].subject" -o tsv
```

**AADSTS700213** specifically means the *subject* did not match, which is this.
**AADSTS700211** means the *issuer* did not — usually the cluster was recreated
and its OIDC issuer URL changed.

### It fails for the first few minutes after creating the identity, then works

Expected. Federated identity credentials take time to propagate across a region,
and Microsoft documents that a token request made minutes after creating one can
fail with AADSTS70021 while caches still hold old data. The operator retries
with backoff. Do not go looking for a misconfiguration on a brand-new identity.

### Imports fail with 403 and the role assignment looks correct

Check that the vault has RBAC authorization enabled. Under the legacy
access-policy model, role assignments are simply ignored.

```console
$ az keyvault show -n my-vault --query properties.enableRbacAuthorization
```

### The listener went down and recovered on its own hours later

Application Gateway silently disables a listener whose certificate it can no
longer fetch, and only retries on its four-hourly poll. With a handful of
wildcard listeners, one Key Vault misconfiguration takes down a large share of
traffic this way.

Alert on the gateway's Resource Health, and on
`certsync_certificate_not_after_timestamp_seconds` — the metric that catches
"operator running but certificates going stale", which reconcile counters
cannot.

### Uninstalling hangs on delete

Delete the operator's custom resources **while the operator is still running**.
Only it removes its own finalizer, so a `kubectl delete` after the deployment is
gone blocks forever. If you are already stuck:

```console
$ kubectl patch keyvaultcertificatesync <name> -n <ns> \
    --type=merge -p '{"metadata":{"finalizers":null}}'
```

Nothing is ever deleted from Key Vault by either path. A listener may still be
serving the certificate.
