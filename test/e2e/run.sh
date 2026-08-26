#!/usr/bin/env bash
#
# Runs the end-to-end suite against a real Kubernetes cluster.
#
# The operator under test is given nothing but a token for its own
# ServiceAccount, bound to the ClusterRole this repo generates. That is the
# point of the exercise: envtest reconcilers run with admin credentials, so a
# missing RBAC rule is invisible there and only appears in production.
#
# Usage:
#   test/e2e/run.sh                  # uses the current kubectl context
#   KUBECONFIG=... test/e2e/run.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

KUBECTL="${KUBECTL:-kubectl}"
NAMESPACE="${E2E_NAMESPACE:-keyvault-certoperator-e2e}"
SA="${E2E_SERVICE_ACCOUNT:-keyvault-certoperator}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# The fake Key Vault answers on a real *.vault.azure.net name over port 443, so
# that the SDK's challenge-resource verification is exercised rather than
# disabled. Both names have to resolve to loopback.
if [[ "${E2E_SKIP_HOSTS:-0}" != "1" ]]; then
  for host in e2e-fake.vault.azure.net login.microsoftonline.com; do
    if ! grep -qE "^127\.0\.0\.1[[:space:]]+$host\b" /etc/hosts 2>/dev/null; then
      echo "==> Mapping $host to loopback (needs write access to /etc/hosts)"
      echo "127.0.0.1 $host" >> /etc/hosts
    fi
  done
fi

echo "==> Clearing anything left by a previous run"
# The vault URL is generated per run, so a resource left behind would point the
# operator at a dead endpoint.
#
# Deletion is issued without --wait and the finalizers are then stripped by
# hand. The operator's finalizer can only be removed by the operator, so a
# blocking delete would hang here: nothing is running yet to release it. The
# same applies when uninstalling for real -- delete the resources while the
# operator is still running, or strip the finalizers as below.
$KUBECTL delete wildcardcertificatepolicy --all --ignore-not-found --wait=false >/dev/null 2>&1 || true
$KUBECTL delete namespace e2e-certs e2e-apps --ignore-not-found --wait=false >/dev/null 2>&1 || true

$KUBECTL delete certificates.cert-manager.io --all -n e2e-certs --ignore-not-found --wait=false >/dev/null 2>&1 || true

for kind in wildcardcertificatepolicies keyvaultcertificatesyncs; do
  while read -r ns name; do
    [[ -z "${name:-}" ]] && continue
    if [[ "$ns" == "<none>" ]]; then
      $KUBECTL patch "$kind" "$name" --type=merge -p '{"metadata":{"finalizers":null}}' >/dev/null 2>&1 || true
    else
      $KUBECTL patch "$kind" "$name" -n "$ns" --type=merge -p '{"metadata":{"finalizers":null}}' >/dev/null 2>&1 || true
    fi
  done < <($KUBECTL get "$kind" -A --no-headers -o custom-columns=NS:.metadata.namespace,N:.metadata.name 2>/dev/null || true)
done

for ns in e2e-certs e2e-apps; do
  for _ in $(seq 1 60); do
    $KUBECTL get namespace "$ns" >/dev/null 2>&1 || break
    sleep 2
  done
done

CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.21.1}"

if [[ "${E2E_CERT_MANAGER:-0}" == "1" ]]; then
  echo "==> Installing cert-manager ${CERT_MANAGER_VERSION}"
  $KUBECTL apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml" >/dev/null

  echo "==> Waiting for cert-manager to become available"
  $KUBECTL wait --for=condition=Available --timeout=300s \
    -n cert-manager deployment/cert-manager deployment/cert-manager-webhook deployment/cert-manager-cainjector

  # The webhook validates every cert-manager resource, and it accepts traffic a
  # little after the Deployment reports Available. Retry rather than racing it.
  echo "==> Creating the CA issuer chain"
  for attempt in $(seq 1 30); do
    if $KUBECTL apply -f test/e2e/testdata/issuer.yaml >/dev/null 2>&1; then break; fi
    if [[ "$attempt" == "30" ]]; then
      echo "the cert-manager webhook never accepted the issuer manifests"
      $KUBECTL apply -f test/e2e/testdata/issuer.yaml
      exit 1
    fi
    sleep 5
  done

  echo "==> Waiting for the root and intermediate certificates to be issued"
  $KUBECTL wait --for=condition=Ready --timeout=180s -n cert-manager certificate/e2e-root
  $KUBECTL wait --for=condition=Ready --timeout=180s -n cert-manager certificate/e2e-ca
fi

echo "==> Installing CRDs"
$KUBECTL apply -f config/crd/bases/ >/dev/null
# The operator creates cert-manager Certificates. Only the CRD is needed; the
# cert-manager controller itself is not exercised here.
$KUBECTL apply -f test/testdata/crds/ >/dev/null

echo "==> Creating the operator's ServiceAccount and RBAC"
$KUBECTL create namespace "$NAMESPACE" --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
$KUBECTL create serviceaccount "$SA" -n "$NAMESPACE" --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null

# Exactly the ClusterRole that ships with the operator, no more.
$KUBECTL apply -f config/rbac/role.yaml >/dev/null
$KUBECTL create clusterrolebinding "${SA}-e2e" \
  --clusterrole=manager-role \
  --serviceaccount="${NAMESPACE}:${SA}" \
  --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
# Leader election is disabled for the test, but the lease permission is part of
# the shipped configuration, so grant it the same way the chart does.
$KUBECTL create role "${SA}-leader-election" -n "$NAMESPACE" \
  --verb=get,list,watch,create,update,patch,delete --resource=leases.coordination.k8s.io \
  --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
$KUBECTL create rolebinding "${SA}-leader-election" -n "$NAMESPACE" \
  --role="${SA}-leader-election" --serviceaccount="${NAMESPACE}:${SA}" \
  --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null

echo "==> Minting a ServiceAccount token for the operator"
TOKEN="$($KUBECTL create token "$SA" -n "$NAMESPACE" --duration=2h)"
SERVER="$($KUBECTL config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
$KUBECTL config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
  | base64 -d > "$WORKDIR/ca.crt" 2>/dev/null || true

OPERATOR_KUBECONFIG="$WORKDIR/operator.kubeconfig"
if [[ -s "$WORKDIR/ca.crt" ]]; then
  $KUBECTL config set-cluster e2e --server="$SERVER" --certificate-authority="$WORKDIR/ca.crt" \
    --embed-certs=true --kubeconfig="$OPERATOR_KUBECONFIG" >/dev/null
else
  $KUBECTL config set-cluster e2e --server="$SERVER" --insecure-skip-tls-verify=true \
    --kubeconfig="$OPERATOR_KUBECONFIG" >/dev/null
fi
$KUBECTL config set-credentials operator --token="$TOKEN" --kubeconfig="$OPERATOR_KUBECONFIG" >/dev/null
$KUBECTL config set-context e2e --cluster=e2e --user=operator --kubeconfig="$OPERATOR_KUBECONFIG" >/dev/null
$KUBECTL config use-context e2e --kubeconfig="$OPERATOR_KUBECONFIG" >/dev/null

echo "==> Building the manager"
go build -o "$WORKDIR/manager" ./cmd/manager

echo "==> Running the end-to-end suite"
E2E_KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}" \
E2E_OPERATOR_KUBECONFIG="$OPERATOR_KUBECONFIG" \
E2E_OPERATOR_BIN="$WORKDIR/manager" \
E2E_CERT_MANAGER="${E2E_CERT_MANAGER:-0}" \
  go test -tags e2e -count=1 -v -timeout 20m ./test/e2e/
