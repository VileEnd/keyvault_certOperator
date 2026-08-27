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
Ingress rules/TLS · Gateway listeners · HTTPRoute hostnames
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

Full setup guide, including troubleshooting: **[docs/azure-setup.md](docs/azure-setup.md)**.

### 1. Azure

**Terraform** ([module reference](terraform/), [complete example](terraform/examples/aks)):

```hcl
module "certoperator_identity" {
  source = "github.com/VileEnd/keyvault_certOperator//terraform?ref=v0.1.1"

  resource_group_name = "my-rg"
  location            = "westeurope"
  key_vault_id        = data.azurerm_key_vault.this.id
  oidc_issuer_url     = data.azurerm_kubernetes_cluster.this.oidc_issuer_url
}
```

**Or the Azure CLI:**

```bash
export SUBSCRIPTION_ID=... RESOURCE_GROUP=... CLUSTER_NAME=... KEYVAULT_NAME=...
./config/azure/setup.sh
```

Either way you get a user-assigned managed identity, federated to the operator's
ServiceAccount, holding **Key Vault Certificates Officer** scoped to the vault
only. Set `USE_CUSTOM_ROLE=1` (or `use_import_only_role = true`) for the
narrower import-only role in `config/azure/keyvault-import-only-role.json` — the
built-in officer role also permits delete and purge, and there is no built-in
import-only role.

The cluster needs `oidc_issuer_enabled` **and** `workload_identity_enabled`, and
the vault needs RBAC authorization rather than access policies. Neither is a
default.

### 2. Install

```bash
helm upgrade --install keyvault-certoperator \
  oci://ghcr.io/vileend/charts/keyvault-certoperator --version 0.1.1 \
  --namespace keyvault-certoperator-system --create-namespace \
  --set azure.clientId=<managed-identity-client-id> \
  --set serviceAccount.name=keyvault-certoperator
```

Or with kustomize, in one URL:

```bash
kubectl apply -f https://github.com/VileEnd/keyvault_certOperator/releases/download/v0.1.1/install.yaml
```

From a clone, `./charts/keyvault-certoperator` and `make deploy IMG=<your-image>`
both still work; that is the development path.

> **Upgrading from a clone predating v0.1.1.** The CRDs used to sit in the
> chart's `crds/` directory, which Helm installs once and never updates. They
> are now ordinary templates, so `helm upgrade` keeps them current — but Helm
> will not adopt objects it did not create, and refuses the upgrade by name:
>
> ```
> invalid ownership metadata; label validation error: missing key
> "app.kubernetes.io/managed-by": must be set to "Helm"
> ```
>
> Hand them over once, and it proceeds:
>
> ```bash
> for crd in keyvaultcertificatesyncs wildcardcertificatepolicies; do
>   kubectl label    crd $crd.certsync.vileend.io app.kubernetes.io/managed-by=Helm --overwrite
>   kubectl annotate crd $crd.certsync.vileend.io \
>     meta.helm.sh/release-name=keyvault-certoperator \
>     meta.helm.sh/release-namespace=keyvault-certoperator-system --overwrite
> done
> ```
>
> `helm uninstall` leaves the CRDs in place (`crds.keep`, on by default), since
> deleting a CRD deletes every custom resource of that kind with it.

> **Pin the ServiceAccount name.** The federated credential matches
> `system:serviceaccount:<ns>:<name>` as a literal string, and the two install
> paths disagree: Helm names it after the release, kustomize appends
> `-controller-manager`. A mismatch fails at token exchange with AADSTS70021,
> which never mentions that a name is wrong. The Terraform module's `helm_values`
> output wires this for you.

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
| `discovery.gateways` | `true` | Gateway listener hostnames. Same startup constraint. See below. |
| `issueZoneWildcards` | `false` | Issue `*.<zone>` for every zone even if nothing routes it yet. |
| `discovery.namespaceSelector` | all | Narrow discovery by namespace labels. |
| `grouping` | `PerZone` | One SAN certificate per zone, or `PerWildcard`. |
| `issuerRef` | — | Referenced, never created. Must use a DNS-01 solver. |
| `certificateNamespace` | — | Where Certificates, Secrets and syncs are created. |
| `orphanPolicy` | `Retain` | `Prune` also deletes no-longer-required resources. |

#### Gateway API (Envoy Gateway, Istio)

Set `discovery.ingress: false` if you route entirely through Gateway API, and
leave both Gateway API sources on:

```yaml
spec:
  discovery:
    ingress: false
    httpRoutes: true
    gateways: true
```

**Both Gateway API sources are needed, and `gateways` is the one that usually
matters.** An HTTPRoute states `spec.hostnames` only to *narrow* what its
listener already allows; leaving it empty inherits the listener's hostnames.
So in the common arrangement — one wildcard listener fronting many routes —
the hostname exists only on the `Gateway`, and reading HTTPRoutes alone
discovers nothing at all.

Listener protocol is ignored on purpose. Behind Application Gateway the
in-cluster listener is often plain HTTP, because TLS was already terminated
upstream; that is exactly the topology this operator serves, and the hostname is
still a hostname the cluster routes.

A listener with **no** hostname matches everything the gateway receives. There
is no concrete name to derive a certificate from, so it contributes nothing
rather than a guess.

Two operational notes:

- Gateway API CRDs must be installed **before the operator starts** —
  controller-runtime cannot open an informer for a type the API server does not
  serve. Installing Gateway API afterwards needs a restart. The startup log says
  which sources are active.
- `orphanPolicy: Prune` is guarded, but know what the guard does. Pruning is
  judged against the current discovery pass, so it is withheld when that pass
  cannot be trusted: when it planned **no certificates at all** — which is
  indistinguishable from a selector matching nothing or every source switched
  off — or when a source the policy **explicitly** enabled was unavailable at
  startup. Either case reports `Ready=False` with reason `PruneWithheld` and
  deletes nothing, because deleting a generated `Certificate` destroys the
  issued Secret and forces re-issuance against Let's Encrypt's duplicate limit.
  `issueZoneWildcards: true` removes the empty-pass case outright by making the
  plan independent of discovery.

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
`x.com` nor `a.b.x.com` — Application Gateway's own docs state this outright. The
apex is added as its own SAN and a deeper host gets a wildcard for its immediate
parent. A listener accepts at most **five host names**, and a listener serving
several needs a **SAN certificate** covering them, so
`status.applicationGateway.listeners` is pre-split to respect both rules.

**The certificate format follows Azure's stated requirements.** Full chain with
the leaf first (the root is documented as optional, which is why Let's Encrypt's
`fullchain` works); TripleDES-SHA1 encryption, which Azure names as the
maximum-compatibility choice and which is what the default `legacy` profile
produces; private key included; `contentType: application/x-pkcs12`. Switching to
`modern` produces AES-256-CBC, which the same Azure page lists as a known cause
of certificate failures — test it before adopting it. No `commonName` is set on
generated certificates, following cert-manager's explicit guidance that TLS
clients ignore it whenever SANs are present.

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

### Test layers

| Layer | What it runs against | Needs |
|---|---|---|
| `internal/domain` | A generated test CA covering RSA and ECDSA, PKCS#8 / PKCS#1 / SEC1 keys, wildcard SANs, out-of-order and broken chains, expired certificates | nothing |
| `internal/app` | Hand-written fakes for the four ports | nothing |
| `internal/infra/pkcs12` | Real encode/decode round trips across all three profiles | nothing |
| `internal/infra/azure` | The Azure SDK's own fake server transport, driving the real client pipeline | nothing |
| `internal/infra/kube` | controller-runtime's fake client | nothing |
| `internal/controller` | envtest: a real API server, both controllers, a fake vault | envtest binaries |

| `test/e2e` | A real cluster, the real built binary, a real HTTPS Key Vault endpoint | a cluster (`make e2e`) |
| `test/e2e` full stack | The above **plus cert-manager actually issuing** the certificate | a cluster + cert-manager (`make e2e-fullstack`) |

Everything except the controller and e2e suites runs with no cluster and no Azure
account. The controller suite skips cleanly if the envtest binaries are missing,
so `go test ./...` is still useful on a bare checkout.

### End-to-end

```bash
make e2e          # against the current kubectl context (k3s, kind, AKS, ...)
make e2e-cleanup
```

This runs the operator as a **separately built binary** against a real API
server, holding nothing but a token for its own ServiceAccount bound to the
ClusterRole this repo generates. That is the point: envtest reconcilers run with
admin credentials, so a missing RBAC rule is invisible there and would surface
only in production.

The Azure side is a fake Key Vault that speaks the real REST protocol over real
HTTPS. It answers an unauthenticated request with a `WWW-Authenticate` challenge
exactly as Key Vault does — which matters, because the SDK deliberately strips
the request body for that first probe so certificate material is never sent to an
endpoint it has not yet authenticated against. Serving the Entra endpoints too
means the workload identity credential genuinely runs. The fake also parses every
upload as PKCS#12, so an archive Key Vault would reject fails the test here.

It runs on `e2e-fake.vault.azure.net` mapped to loopback on port 443, because the
SDK verifies the challenge resource against the vault host and that comparison
includes any non-default port. Using a real vault hostname exercises that
verification instead of switching it off. The script adds the `/etc/hosts`
entries and needs root to bind 443.

What this covers that envtest cannot: the generated ClusterRole is sufficient;
the Azure request is well formed on the wire (TLS, challenge, token, base64, the
certificate policy shape, tags, content type); `cmd/manager` actually wires up
and runs, label-scoped cache included.

### Full stack, with cert-manager issuing

```bash
make e2e-fullstack
```

The plain suite hand-writes the TLS Secret, so nothing before that point is
proven. This one installs cert-manager, creates a self-signed root and a CA
`ClusterIssuer` from it, and then exercises the whole pipeline with nobody
faking the middle:

```
Ingress hostnames
  -> the policy plans a covering wildcard
  -> the operator creates a cert-manager Certificate
  -> cert-manager actually issues it and writes the Secret
  -> the Secret carries the managed label, so it is inside the operator's cache
  -> the operator parses it and imports it into the mock Key Vault
```

A local CA is used rather than ACME because wildcards require a DNS-01 solver and
public DNS, and what needs proving here is everything *after* issuance. The test
asserts the certificate that reached Key Vault carries the wildcard and apex
SANs, arrived as PKCS#12 with its issuing chain, and was imported exactly once.

CI additionally installs the chart into k3s with the freshly built image and
asserts the operator becomes ready **with no Azure reachable at all** — a
deliberate design property, since probes that depended on Key Vault would turn an
Azure outage into a CrashLoopBackOff — and that the hardened pod spec
(`runAsNonRoot`, `readOnlyRootFilesystem`, no privilege escalation, the workload
identity label) is actually in effect on the running pod.

The assertion that matters most is in the controller suite: after the first
import, a repeatedly-reconciled unchanged certificate must produce **zero**
further imports. Key Vault versions are permanent and each one is a candidate
Application Gateway rotation, so a regression there degrades the vault quietly.

### Cutting a release

From the Actions tab: run **Release**, give it the tag (`v0.1.1`) and tick
**create_tag**. It does the whole thing in one run — creates the tag, builds and
pushes the multi-arch image, publishes the chart to
`oci://ghcr.io/vileend/charts`, and opens a GitHub release with `install.yaml`
attached.

Tagging lives inside that workflow rather than in one of its own, for two
reasons. The tag is minted only *after* the tests pass and the tag is confirmed
to agree with `Chart.yaml` — a tag is permanent, so it should not be spent on a
commit that does not build. And a tag pushed by `GITHUB_TOKEN` does not start a
new workflow run, so a separate tagging workflow would create the tag and
publish nothing.

Pushing a tag by hand works too, and triggers the same workflow:

```bash
git tag -a v0.1.1 -m v0.1.1 && git push origin v0.1.1
```

If publishing fails after the tag exists, re-run **Release** with the same tag
and **create_tag** off, rather than deleting and re-pushing a released tag. The
workflow definition comes from the default branch, so a fix there takes effect
even though the tag's own tree still holds the old file.

`v0.1.0` is such a tag and is deliberately left in place: its run created the
tag and then failed on the image build, so it published nothing. The first
release is `v0.1.1`.

## Uninstalling

Delete the `WildcardCertificatePolicy` and `KeyVaultCertificateSync` resources
**while the operator is still running**. They carry a finalizer that only the
operator removes, so deleting them after it is gone leaves them — and any
namespace containing them — stuck terminating. If that has already happened:

```bash
kubectl patch keyvaultcertificatesync <name> -n <ns> \
  --type=merge -p '{"metadata":{"finalizers":null}}'
```

The finalizer never blocks on Azure, and nothing is ever deleted from Key Vault.

## Not in scope

Deleting or disabling Key Vault certificates; writing Application Gateway
configuration via ARM; implementing ACME; managing the ACME issuer. Each of these
would need privileges the operator deliberately does not hold.

## License

MIT. See [LICENSE](LICENSE).
