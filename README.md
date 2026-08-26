# keyvault-certoperator

A Kubernetes operator for AKS that keeps wildcard TLS certificates flowing from
in-cluster issuance into **Azure Key Vault**, so **Application Gateway**
listeners can serve them and pick up renewals on their own.

It does two things:

1. **Discovers** the hostnames your cluster routes (Ingress and Gateway API
   HTTPRoute), works out which wildcard certificates cover them, and has
   **cert-manager** issue those.
2. **Syncs** the resulting certificates into Key Vault, importing only when
   something has actually changed.

You can use either half on its own.

## Why wildcards, and why not AGIC

Application Gateway Ingress Controller creates one backend pool, one backend
HTTP setting, one listener and one SSL certificate per Ingress or service. Those
all sit under Application Gateway's per-gateway ceilings — **100 backend pools,
100 backend HTTP settings, 100 active listeners, 100 SSL certificates** — which
are hard and cannot be raised by a support ticket. Around a hundred applications
you hit the wall, and it is a cliff rather than a slope: once a create is
rejected, AGIC stops reconciling the whole gateway, so unrelated changes stall
too.

> On **WAF_v2 with CRS 3.1 or older** those limits drop to **40**. Check your
> ruleset version before sizing anything.

Putting a handful of wildcard certificates on the gateway and routing everything
behind one in-cluster proxy sidesteps this entirely. Three wildcards is three
listeners, three sites, three certificates, **one** backend pool and **one**
backend HTTP setting — roughly 3% of every relevant budget, no matter how many
services sit behind the proxy.

Two things worth knowing before you commit:

- **AGIC and hand-placed listeners cannot share a gateway.** AGIC overwrites any
  configuration it does not own. If you are dropping AGIC, just never re-enable
  the add-on against that gateway.
- **Application Gateway for Containers is not the escape hatch it looks like.**
  It still caps at 100 services per AGC and it does not support Key Vault
  certificates at all — certificates must be Kubernetes Secrets.

## How it works

```
Ingress / HTTPRoute hostnames
        │  discovery (zone allowlist + public-suffix guard)
        ▼
WildcardCertificatePolicy ──creates──► cert-manager Certificate ──► TLS Secret
        │                                    (ACME DNS-01, Azure DNS)     │
        └──creates──► KeyVaultCertificateSync ◄───────────watches─────────┘
                              │
                              │  import only when the leaf or chain changed
                              ▼
                     Azure Key Vault certificate
                              │
                              │  versionless secret URI, polled every ~4h
                              ▼
              Application Gateway HTTPS listener
```

Issuance is delegated, not reimplemented. cert-manager already performs ACME
DNS-01 against Azure DNS with workload identity and owns renewal timing, so this
operator needs **no Azure DNS permissions at all**.

**Wildcards need no pods.** Wildcard certificates cannot use HTTP-01 — Let's
Encrypt requires DNS-01, which never touches the cluster. There is no challenge
to serve, so no pod, Service, backend or Ingress is involved in issuance.

## Quick start

### 1. Azure

```bash
export SUBSCRIPTION_ID=... RESOURCE_GROUP=... CLUSTER_NAME=... KEYVAULT_NAME=...
./config/azure/setup.sh
```

This enables the AKS OIDC issuer and workload identity, creates a user-assigned
managed identity, federates it to the operator's ServiceAccount, and grants it
**Key Vault Certificates Officer** scoped to the vault only. Set
`USE_CUSTOM_ROLE=1` to use the narrower import-only role in
`config/azure/keyvault-import-only-role.json` instead — the built-in officer role
also permits delete and purge, and there is no built-in import-only role.

### 2. Install

```bash
helm upgrade --install keyvault-certoperator ./charts/keyvault-certoperator \
  --namespace keyvault-certoperator-system --create-namespace \
  --set azure.clientId=<managed-identity-client-id>
```

Or with kustomize: `make deploy IMG=<your-image>`.

### 3. Declare a policy

```yaml
apiVersion: certsync.vileend.io/v1alpha1
kind: WildcardCertificatePolicy
metadata:
  name: public-sites
spec:
  zones: [x.com, sub.x.com]     # required allowlist
  issuerRef:
    name: letsencrypt-dns       # must use a DNS-01 solver
    kind: ClusterIssuer
  certificateNamespace: cert-system
  keyVault:
    name: my-vault
```

### 4. Wire Application Gateway

The policy reports exactly what to configure:

```bash
kubectl get wildcardcertificatepolicy public-sites \
  -o jsonpath='{.status.applicationGateway.listeners}' | jq
```

```json
[{"hostnames": ["*.x.com", "x.com"],
  "keyVaultSecretID": "https://my-vault.vault.azure.net/secrets/wildcard-x-com"}]
```

Apply that with Terraform, Bicep or the CLI. The operator holds **no ARM
permissions** and never writes gateway configuration itself.

See [docs/application-gateway.md](docs/application-gateway.md) for the wiring
details and the failure modes worth alerting on.

## The two APIs

### `WildcardCertificatePolicy` (cluster-scoped)

Discovery and issuance. See
[config/samples](config/samples/certsync_v1alpha1_wildcardcertificatepolicy.yaml)
for a commented example.

| Field | Default | Notes |
|---|---|---|
| `zones` | — | **Required allowlist.** Nothing outside these zones is ever issued. |
| `maxCertificates` | `10` | Overflow is reported in status, not issued. |
| `discovery.ingress` | `true` | Discover from `networking.k8s.io` Ingresses. |
| `discovery.httpRoutes` | `true` | Only watched if Gateway API CRDs exist at operator start. |
| `discovery.namespaceSelector` | all | Narrow discovery by namespace labels. |
| `grouping` | `PerZone` | One SAN certificate per zone, or `PerWildcard`. |
| `issuerRef` | — | Referenced, never created. Must use a DNS-01 solver. |
| `certificateNamespace` | — | Where Certificates, Secrets and syncs are created. |
| `orphanPolicy` | `Retain` | `Prune` also deletes no-longer-required resources. |

### `KeyVaultCertificateSync` (namespaced)

One certificate, one vault. Generated by a policy, or written by hand if you
manage certificates yourself.

| Field | Default | Notes |
|---|---|---|
| `source.secretRef.name` | — | A `kubernetes.io/tls` Secret in the **same namespace**. |
| `keyVault.name` / `keyVault.vaultURL` | — | Exactly one. `vaultURL` for sovereign clouds or private endpoints. |
| `keyVault.certificateName` | derived | Derived from the SANs, e.g. `*.x.com` → `wildcard-x-com`. |
| `syncPolicy.resyncInterval` | `1h` | Catches drift applied to Key Vault out of band. |
| `syncPolicy.pkcs12Profile` | `legacy` | `legacy`, `passwordless` or `modern`. |

> **The Secret must carry `certsync.vileend.io/managed: "true"`.** The operator's
> cache only watches labelled Secrets, so an unlabelled one is invisible to it by
> design. Generated certificates get the label automatically via cert-manager's
> `secretTemplate`.

## Design decisions worth knowing

**Imports are not idempotent, so the operator checks first.** Every
`ImportCertificate` call mints a new Key Vault version. Versions can never be
deleted, more than 500 breaks the vault's backup operation, the throttle is 300
per 10 seconds, and each new version is a candidate Application Gateway rotation
within four hours. So each reconcile does one cheap `GetCertificate` and imports
only on a real difference. In steady state the operator makes no writes at all.

**The leaf thumbprint is not enough.** Key Vault's `X509Thumbprint` covers the
leaf only. When a CA rotates its intermediates — Let's Encrypt has done this
several times — the leaf stays byte-identical while the stored chain goes stale.
The operator therefore stamps a `chain-sha256` tag and compares that too. Tags
come back free on `GetCertificate`; reading the stored chain instead would need
`secrets/getSecret`, which would also expose the private key, so that permission
is never requested.

**Nothing is deleted from Key Vault.** Not on resource deletion, not under
`orphanPolicy: Prune`. An Application Gateway listener may still be serving a
certificate, and deleting or disabling the version it holds takes that listener
down.

**Discovery is fenced.** Anyone who can create an Ingress could otherwise trigger
ACME issuance and spend your Let's Encrypt rate limit. Three guards, none
optional: a required zone allowlist, a Public Suffix List check that makes
`*.com` and `*.co.uk` unreachable, and a certificate cap. Anything skipped is
reported in `status.skippedHosts` with a reason — never dropped silently.

**Wildcards match exactly one label.** `*.x.com` covers `a.x.com` but neither
`x.com` nor `a.b.x.com`. The apex is added as its own SAN and a deeper host gets
a wildcard for its immediate parent. Application Gateway allows at most **five
host names per listener**, so `status.applicationGateway.listeners` is
pre-split to respect that.

**Least privilege throughout.** Secrets are read-only and cache-restricted by
label. The Azure identity is scoped to a single vault. The operator needs no
Azure DNS and no ARM permissions. Neither health probe touches Azure, so a Key
Vault outage cannot turn into a CrashLoopBackOff that also costs leader election.

## Architecture

Onion layering, dependencies pointing strictly inward:

```
cmd/manager/          composition root — the only package that knows everything
api/v1alpha1/         CRD types
internal/domain/      pure core: parsing, chain ordering, wildcard planning, the
                      import decision. Standard library only. No k8s, no Azure.
internal/app/         use cases + the ports they depend on
internal/infra/       adapters: Kubernetes, Azure Key Vault, PKCS#12
internal/controller/  thin Kubernetes adapters over the use cases
```

The sync workflow exists once, in `app.Syncer`. The import/skip rule exists once,
in `domain.Decide`. The host-to-certificate rule exists once, in
`domain.BuildPlan`. Everything else translates between those and Kubernetes.

## Development

```bash
make test          # unit suites + envtest controller suite
make test-unit     # no cluster, no Azure
make lint
make check-manifests   # fail if generated files drift
make run           # against your current kubecontext, using az-CLI credentials
```

Requires Go 1.26 (the toolchain directive fetches it automatically). Everything
else — controller-gen, setup-envtest, golangci-lint, kustomize — is installed
into `./bin` on demand.

The domain layer needs neither a cluster nor an Azure account, and the Key Vault
adapter is tested against the Azure SDK's own fake server transport.

## Not in scope

Deleting or disabling Key Vault certificates; writing Application Gateway
configuration via ARM; implementing ACME; managing the ACME issuer. Each of these
would need privileges the operator deliberately does not hold.

## License

MIT. See [LICENSE](LICENSE).
