# Wiring Application Gateway

This operator stops at Key Vault. It reports exactly what to configure on the
gateway, and you apply it with Terraform, Bicep or the CLI. That boundary is
deliberate: writing gateway configuration would require
`Microsoft.Network/applicationGateways/write`, and the operator would rather not
hold it.

## What the operator gives you

```bash
kubectl get wildcardcertificatepolicy public-sites \
  -o jsonpath='{.status.applicationGateway.listeners}' | jq
```

```json
[
  {
    "hostnames": ["*.x.com", "x.com"],
    "keyVaultSecretID": "https://my-vault.vault.azure.net/secrets/wildcard-x-com"
  }
]
```

For a single sync resource, the same value is at
`status.secretIdentifier`.

## Prerequisites

| Requirement | Detail |
|---|---|
| SKU | **v2 only** (`Standard_v2` / `WAF_v2`). |
| Identity | A **user-assigned** managed identity assigned to the gateway. System-assigned is not supported, and a gateway can hold only one. |
| Role | That identity needs **Key Vault Secrets User** on the vault. Not Certificates User — the gateway resolves `/secrets/`, so `secrets/getSecret` is the true minimum. |
| Certificate | Software-validated with an exportable private key. HSM-validated certificates are not supported. |
| Portal | You **cannot** configure a Key Vault certificate reference through the portal when the vault uses RBAC. Use ARM, Bicep, CLI or PowerShell for the initial wiring. |

Use a **separate identity** from the operator's. The operator writes
certificates; the gateway only reads the secret behind one. Sharing an identity
gives the gateway write access it has no use for.

## Wiring it

```bash
# The certificate object on the gateway
az network application-gateway ssl-cert create \
  --resource-group "$RG" --gateway-name "$AGW" \
  --name wildcard-x-com \
  --key-vault-secret-id "https://my-vault.vault.azure.net/secrets/wildcard-x-com"

# A multi-site listener serving up to five host names
az network application-gateway http-listener create \
  --resource-group "$RG" --gateway-name "$AGW" \
  --name https-x-com \
  --frontend-port 443 \
  --ssl-cert wildcard-x-com \
  --host-names "*.x.com" "x.com"
```

Terraform:

```hcl
ssl_certificate {
  name                = "wildcard-x-com"
  key_vault_secret_id = "https://my-vault.vault.azure.net/secrets/wildcard-x-com"
}

http_listener {
  name                 = "https-x-com"
  frontend_port_name   = "https"
  protocol             = "Https"
  ssl_certificate_name = "wildcard-x-com"
  host_names           = ["*.x.com", "x.com"]
}
```

## Rules that bite

**Use the versionless URI.** `https://<vault>.vault.azure.net/secrets/<name>`,
with no trailing version segment. Instances poll Key Vault roughly **every four
hours** and rotate to a newer version automatically. A versioned URI pins the
listener to one version forever and silently disables that rotation — the
listener will happily serve an expired certificate.

**`*.x.com` does not match `x.com`.** A wildcard matches exactly one label, and
Application Gateway's own documentation spells this out. The apex needs its own
entry in `hostNames`, and the certificate needs it as a SAN. The operator plans
for this; just do not trim the list when you apply it.

**Five host names per listener, maximum.** That is a hard limit. A certificate
may carry more SANs than that — `status.applicationGateway.listeners` is
pre-split so each entry is applicable as-is.

**Rule priority matters.** Wildcard listeners must have lower priority (a higher
number) than specific-hostname listeners, or the wildcard swallows the traffic
first. A workable convention: exact hostnames 100–199, wildcards 200–299,
catch-all 300+.

**Re-applying the same URI is not a refresh.** Application Gateway refetches only
when the configured `keyVaultSecretId` *changes*. If you need propagation faster
than the four-hour poll, the documented trick is to set the listener to the
current versioned URI and then back to the versionless one. Any change to the
gateway — even a resource tag — also forces a re-check.

**Never disable or delete the old certificate version** after a rotation until
you have seen the listener serving the new thumbprint. Disabling the version a
listener currently holds produces `SecretDisabled` and takes it down. This
operator never deletes from Key Vault for exactly this reason.

## Networking

If the vault has network restrictions, give both the gateway and the operator a
path to it:

- **Gateway:** add its subnet to the vault's network rules with the
  `Microsoft.KeyVault` service endpoint enabled, or use a private endpoint with
  the `privatelink.vaultcore.azure.net` zone linked to the gateway's VNet.
- **Operator:** the AKS node subnet needs its own rule or the same private
  endpoint. The operator pod is not an Azure trusted service and gets no bypass.

Microsoft's documentation contradicts itself on whether Application Gateway v2
counts as a Key Vault trusted service. Do not rely on the bypass either way —
configure the subnet or private endpoint explicitly and the question stops
mattering.

## Monitoring

**The failure mode that hurts most is silent.** If the gateway loses access to
the vault or cannot find the certificate object, it puts the affected HTTPS
listener into a **disabled** state. Clients get
`ERR_SSL_UNRECOGNIZED_NAME_ALERT`; nothing in the cluster notices. Recovery waits
on the four-hour poll. With only two or three wildcard listeners fronting
everything, one Key Vault misconfiguration is a very large blast radius.

Wire up all three:

1. **Azure Resource Health** on the gateway.
2. The **Azure Advisor** recommendation *"Resolve Azure Key Vault issue for your
   Application Gateway"*.
3. The operator's own expiry metric, which catches the other half of the problem
   — an operator that is running happily while certificates quietly age out:

```promql
# Certificates expiring within 14 days
(certsync_certificate_not_after_timestamp_seconds - time()) < 14 * 24 * 3600

# The operator has not reconciled a resource successfully in an hour
(time() - certsync_last_success_timestamp_seconds) > 3600

# Hostnames the policy is not covering
certsync_hosts_skipped > 0
```

Error codes worth recognising: `ApplicationGatewayKeyVaultSecretException`,
`UserAssignedIdentityDoesNotHaveGetPermissionOnKeyVault`, `SecretDisabled`,
`SecretDeletedFromKeyVault`, `KeyVaultHasRestrictedAccess`, `KeyVaultSoftDeleted`,
`UserAssignedManagedIdentityNotFound`.

## Two things to verify on your own gateway

Microsoft's documentation is genuinely ambiguous on both, and both are cheap to
test:

1. **Does your gateway accept a chain without the root?** One page asks for the
   entire chain "including the root"; another says the root is optional. Let's
   Encrypt's `fullchain` contains leaf and intermediate only. In practice this
   works because ISRG Root X1 is in every trust store — but confirm it rather
   than assume it.
2. **Does the default PKCS#12 profile work for you?** The operator defaults to
   `legacy` (3DES/SHA-1), which is the profile Azure's troubleshooting guidance
   asks for by name, because some Azure services cannot parse AES-256-CBC
   archives. If your vault and gateway are happy with modern algorithms, set
   `syncPolicy.pkcs12Profile: modern`.

Test both against the Let's Encrypt **staging** issuer first, so a mistake cannot
burn your production rate limit.
