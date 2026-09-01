#!/usr/bin/env bash
#
# Provisions the Azure side of keyvault-certoperator:
#   * a user-assigned managed identity for the operator
#   * a federated credential binding it to the operator's ServiceAccount
#   * the Key Vault grant it needs, scoped to the vault -- a role assignment or
#     an access policy, following the vault's own permission model
#
# It also prints the grant Application Gateway needs, which goes to a
# *different* identity and is *narrower*. Never share one identity between the
# operator and the gateway: the operator writes certificates, the gateway only
# reads the secret behind one.
#
# Requires the Azure CLI, logged in, with permission to make that grant.
set -euo pipefail

: "${SUBSCRIPTION_ID:?set SUBSCRIPTION_ID}"
: "${RESOURCE_GROUP:?set RESOURCE_GROUP}"
: "${CLUSTER_NAME:?set CLUSTER_NAME}"
: "${KEYVAULT_NAME:?set KEYVAULT_NAME}"

IDENTITY_NAME="${IDENTITY_NAME:-keyvault-certoperator}"
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-keyvault-certoperator-system}"
# The federated credential matches this as a literal string, so it has to be
# the name that actually exists in the cluster. The two install paths do not
# agree: the Helm chart names the ServiceAccount after the release, while the
# kustomize manifests under config/ prefix it with "-controller-manager".
#
# The default below is the Helm name, because the Helm command this script
# prints is what most people run. It is passed to that command explicitly, so
# the two cannot drift. Override it for the kustomize path:
#
#   SERVICE_ACCOUNT=keyvault-certoperator-controller-manager
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-keyvault-certoperator}"
# Set USE_CUSTOM_ROLE=1 to use the narrower import-only role from
# keyvault-import-only-role.json instead of the built-in officer role. It has no
# effect on an access-policy vault, which ignores roles of either kind.
USE_CUSTOM_ROLE="${USE_CUSTOM_ROLE:-0}"
# rbac, access-policy, or auto (the default) to ask the vault which it uses.
# Setting it explicitly makes this script refuse a vault that disagrees, which
# is the useful thing to do in a pipeline where the vault is supposed to be a
# known quantity.
VAULT_AUTHORIZATION="${VAULT_AUTHORIZATION:-auto}"
case "$VAULT_AUTHORIZATION" in
  auto | rbac | access-policy) ;;
  *) echo "VAULT_AUTHORIZATION must be auto, rbac or access-policy" >&2; exit 1 ;;
esac

az account set --subscription "$SUBSCRIPTION_ID"

echo "==> Ensuring the AKS OIDC issuer and workload identity are enabled"
az aks update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --enable-oidc-issuer \
  --enable-workload-identity \
  --only-show-errors >/dev/null

OIDC_ISSUER=$(az aks show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --query oidcIssuerProfile.issuerUrl -o tsv)

echo "==> Creating the managed identity ${IDENTITY_NAME}"
az identity create \
  --name "$IDENTITY_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --only-show-errors >/dev/null

CLIENT_ID=$(az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" --query clientId -o tsv)
PRINCIPAL_ID=$(az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" --query principalId -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

echo "==> Federating the identity to ${OPERATOR_NAMESPACE}/${SERVICE_ACCOUNT}"
# The audience is fixed across every Azure cloud; do not change it.
az identity federated-credential create \
  --name "fic-${IDENTITY_NAME}" \
  --identity-name "$IDENTITY_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --issuer "$OIDC_ISSUER" \
  --subject "system:serviceaccount:${OPERATOR_NAMESPACE}:${SERVICE_ACCOUNT}" \
  --audience api://AzureADTokenExchange \
  --only-show-errors >/dev/null

VAULT_ID=$(az keyvault show --name "$KEYVAULT_NAME" --query id -o tsv)

# Which grant to make is decided by the vault, not by preference: a role
# assignment on an access-policy vault is accepted and then ignored, and an
# access policy on an RBAC vault likewise. Either mistake applies cleanly and
# surfaces only as a 403 on the first import, which is why this is asked rather
# than assumed. A null means the property was never set, which is the legacy
# access-policy model.
RBAC_ENABLED=$(az keyvault show --name "$KEYVAULT_NAME" --query properties.enableRbacAuthorization -o tsv)
if [[ "$RBAC_ENABLED" == "true" ]]; then
  DETECTED=rbac
else
  DETECTED=access-policy
fi
if [[ "$VAULT_AUTHORIZATION" == "auto" ]]; then
  VAULT_AUTHORIZATION="$DETECTED"
elif [[ "$VAULT_AUTHORIZATION" != "$DETECTED" ]]; then
  echo "VAULT_AUTHORIZATION=${VAULT_AUTHORIZATION} but ${KEYVAULT_NAME} uses ${DETECTED};" \
    "a grant of the wrong kind applies cleanly and then does nothing" >&2
  exit 1
fi
echo "==> ${KEYVAULT_NAME} uses the ${VAULT_AUTHORIZATION} permission model"

if [[ "$VAULT_AUTHORIZATION" == "access-policy" ]]; then
  # Get and Import is the operator's entire Key Vault surface: it reads one
  # certificate by name before deciding whether to import, so it never lists,
  # and the chain digest it compares against travels inside the import request
  # rather than as an update.
  #
  # set-policy *replaces* this principal's entry rather than merging into it. On
  # a fresh identity that is what you want; if the identity is one you already
  # granted something else, read the existing entry back first.
  echo "==> Granting certificate Get and Import as an access policy on the vault"
  az keyvault set-policy \
    --name "$KEYVAULT_NAME" \
    --object-id "$PRINCIPAL_ID" \
    --certificate-permissions get import \
    --only-show-errors >/dev/null
  GRANTED="access policy: certificates Get, Import"
elif [[ "$USE_CUSTOM_ROLE" == "1" ]]; then
  ROLE_NAME="Key Vault Certificate Importer"
  echo "==> Ensuring the custom role '${ROLE_NAME}' exists"
  tmp=$(mktemp)
  sed "s|REPLACE-WITH-SUBSCRIPTION-ID|${SUBSCRIPTION_ID}|" \
    "$(dirname "$0")/keyvault-import-only-role.json" > "$tmp"
  az role definition create --role-definition "$tmp" --only-show-errors >/dev/null 2>&1 || \
    az role definition update --role-definition "$tmp" --only-show-errors >/dev/null
  rm -f "$tmp"
else
  # The only built-in role carrying certificates/import. It also allows delete
  # and purge; use USE_CUSTOM_ROLE=1 if that is too broad for you.
  ROLE_NAME="Key Vault Certificates Officer"
fi

if [[ "$VAULT_AUTHORIZATION" == "rbac" ]]; then
  echo "==> Granting '${ROLE_NAME}' on the vault only, never the subscription"
  az role assignment create \
    --assignee-object-id "$PRINCIPAL_ID" \
    --assignee-principal-type ServicePrincipal \
    --role "$ROLE_NAME" \
    --scope "$VAULT_ID" \
    --only-show-errors >/dev/null
  GRANTED="$ROLE_NAME"
fi

if [[ "$VAULT_AUTHORIZATION" == "access-policy" ]]; then
  GATEWAY_GRANT="az keyvault set-policy --name ${KEYVAULT_NAME} \\
         --object-id <gateway-identity-principal-id> --secret-permissions get"
else
  GATEWAY_GRANT="az role assignment create --role 'Key Vault Secrets User' \\
         --assignee-object-id <gateway-identity-principal-id> \\
         --assignee-principal-type ServicePrincipal --scope ${VAULT_ID}"
fi

cat <<EOF

Done. The operator identity holds ${GRANTED} on ${KEYVAULT_NAME}.

Annotate the operator's ServiceAccount with:

  azure.workload.identity/client-id: ${CLIENT_ID}

Helm:

  helm upgrade --install keyvault-certoperator ./charts/keyvault-certoperator \\
    --namespace ${OPERATOR_NAMESPACE} --create-namespace \\
    --set azure.clientId=${CLIENT_ID} \\
    --set azure.tenantId=${TENANT_ID} \\
    --set serviceAccount.name=${SERVICE_ACCOUNT}

The ServiceAccount name is pinned above on purpose. The federated credential
matches the subject

  system:serviceaccount:${OPERATOR_NAMESPACE}:${SERVICE_ACCOUNT}

as a literal string, and a mismatch fails at token exchange with AADSTS70021,
which reports no matching federated identity record and never mentions that a
name is wrong. If you install some other way, confirm with:

  kubectl get sa -n ${OPERATOR_NAMESPACE}

Still to do, for Application Gateway:

  1. Assign a *separate* user-assigned managed identity to the gateway and give
     it read access to the vault's secrets. The gateway reads /secrets/, not
     /certificates/, even for an object that was uploaded as a certificate, so
     that is its true minimum -- and a grant carrying certificate permissions
     instead fails exactly like no grant at all. On this vault:

       ${GATEWAY_GRANT}
  2. Point each listener at the versionless secret identifier this operator
     reports in status.secretIdentifier. A versioned URI permanently disables
     the four-hourly automatic rotation.
  3. If the vault has a network ACL, add the gateway's subnet explicitly (with
     the Microsoft.KeyVault service endpoint) or use a private endpoint with the
     privatelink.vaultcore.azure.net zone linked. Do not rely on the trusted
     services bypass; Microsoft's own documentation disagrees with itself about
     whether Application Gateway qualifies. The AKS node subnet needs its own
     path to the vault too -- the operator pod is definitely not a trusted
     service.
EOF
