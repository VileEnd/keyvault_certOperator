#!/usr/bin/env bash
#
# Provisions the Azure side of keyvault-certoperator:
#   * a user-assigned managed identity for the operator
#   * a federated credential binding it to the operator's ServiceAccount
#   * the Key Vault role assignment it needs, scoped to the vault
#
# It also prints the role assignment Application Gateway needs, which is a
# *different* identity with a *narrower* role. Never share one identity between
# the operator and the gateway: the operator writes certificates, the gateway
# only reads the secret behind one.
#
# Requires the Azure CLI, logged in, with permission to create role assignments.
set -euo pipefail

: "${SUBSCRIPTION_ID:?set SUBSCRIPTION_ID}"
: "${RESOURCE_GROUP:?set RESOURCE_GROUP}"
: "${CLUSTER_NAME:?set CLUSTER_NAME}"
: "${KEYVAULT_NAME:?set KEYVAULT_NAME}"

IDENTITY_NAME="${IDENTITY_NAME:-keyvault-certoperator}"
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-keyvault-certoperator-system}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-keyvault-certoperator-controller-manager}"
# Set USE_CUSTOM_ROLE=1 to use the narrower import-only role from
# keyvault-import-only-role.json instead of the built-in officer role.
USE_CUSTOM_ROLE="${USE_CUSTOM_ROLE:-0}"

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

if [[ "$USE_CUSTOM_ROLE" == "1" ]]; then
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

echo "==> Granting '${ROLE_NAME}' on the vault only, never the subscription"
az role assignment create \
  --assignee-object-id "$PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "$ROLE_NAME" \
  --scope "$VAULT_ID" \
  --only-show-errors >/dev/null

cat <<EOF

Done. Annotate the operator's ServiceAccount with:

  azure.workload.identity/client-id: ${CLIENT_ID}

Helm:

  helm upgrade --install keyvault-certoperator ./charts/keyvault-certoperator \\
    --namespace ${OPERATOR_NAMESPACE} --create-namespace \\
    --set azure.clientId=${CLIENT_ID} \\
    --set azure.tenantId=${TENANT_ID}

Still to do, for Application Gateway:

  1. Assign a *separate* user-assigned managed identity to the gateway and give
     it "Key Vault Secrets User" on ${KEYVAULT_NAME}. The gateway reads
     /secrets/, not /certificates/, so Secrets User is the true minimum.
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
