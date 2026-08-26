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

Microsoft's own pages disagree here, and the more specific one wins. The
Application Gateway certificate troubleshooting guide is unambiguous:

> Application Gateway v2 doesn't appear on the Key Vault trusted services list.
> Even if `bypass: "AzureServices"` is set, the Application Gateway subnet must
> be explicitly added to the Key Vault network rules, or a private endpoint must
> be configured.

The older "TLS termination with Key Vault certificates" page still describes
Application Gateway as a recognised trusted service. **Do not rely on the
bypass.** Configure the subnet rule or the private endpoint explicitly and the
contradiction stops mattering.

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

## Certificate format: settled, not guesswork

Both of these were open questions during the build and are now answered directly
by Azure's Application Gateway certificate requirements table:

| Requirement | Azure's wording | What the operator does |
|---|---|---|
| Chain | *"Full chain: leaf → intermediate(s) → root (root is optional but recommended)"* | Sends leaf + intermediates. Let's Encrypt's `fullchain` has no root, and that is accepted. |
| Encryption | *"TripleDES-SHA1 recommended (maximum compatibility)"* | Defaults to the `legacy` profile, which is exactly TripleDES-SHA1. |
| Password | *"Can be blank or have a password (Key Vault handles this)"* | Either works; Key Vault strips it on import. |
| Private key | *"Must be included"* | Always included. |
| Format | PKCS#12 (PFX) or PEM | PKCS#12, with `contentType: application/x-pkcs12`. |

**Do not switch to `pkcs12Profile: modern` without testing.** The same Azure page
lists *"The PFX file uses a nonstandard encryption algorithm (for example,
`AES-256-CBC` instead of `TripleDES-SHA1`)"* as a known cause of certificate
failures — and AES-256-CBC is precisely what the `modern` profile produces. The
`legacy` default is the documented-compatible choice, and the weak encryption is
irrelevant here: the archive exists only in memory for one call to Key Vault,
which then strips the password and re-encodes it anyway.

**No `commonName` is set on the generated certificates.** cert-manager's own
guidance is explicit — *"Avoid using commonName for DNS names in end-entity
(leaf) certificates… use dnsNames exclusively"* — because TLS clients ignore the
common name whenever subject alternative names are present, and a value over 64
characters gets the CSR rejected outright. The SANs are what Application Gateway
matches on.

Still worth doing once against a scratch vault before you trust it in
production: import a certificate, point a test listener at it, and confirm the
gateway serves it. Use the Let's Encrypt **staging** issuer for that, so a
mistake cannot burn your production rate limit.
