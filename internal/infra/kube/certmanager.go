package kube

import (
	"context"
	"fmt"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
)

// certificateGroupKind is the cert-manager type this operator creates.
var certificateGroupKind = schema.GroupKind{Group: "cert-manager.io", Kind: "Certificate"}

// CertificateWriter creates and updates the cert-manager Certificate resources
// that back each planned wildcard.
//
// Issuance is delegated rather than implemented. cert-manager already performs
// ACME DNS-01 against Azure DNS with workload identity, owns renewal timing and
// tracks rate limits; re-implementing that here would duplicate it badly. It
// also means this operator needs no Azure DNS permissions at all.
type CertificateWriter struct {
	Client client.Client
	Mapper meta.RESTMapper
}

// NewCertificateWriter wires a CertificateWriter.
func NewCertificateWriter(c client.Client, mapper meta.RESTMapper) *CertificateWriter {
	return &CertificateWriter{Client: c, Mapper: mapper}
}

// Available reports whether cert-manager's Certificate CRD is installed.
//
// This is probed on every reconcile rather than once at startup, using a mapper
// that reloads on a miss, so installing cert-manager after the operator does not
// require a restart. When it is missing the policy controller degrades loudly --
// it still reports the certificates the cluster needs -- instead of failing.
func (w *CertificateWriter) Available(_ context.Context) (bool, error) {
	_, err := w.Mapper.RESTMapping(certificateGroupKind, "v1")
	if err == nil {
		return true, nil
	}
	// IsNoMatchError already covers both NoKindMatchError and
	// NoResourceMatchError, which is the whole "the API server does not serve
	// this" family.
	if meta.IsNoMatchError(err) {
		return false, nil
	}
	return false, fmt.Errorf("checking for the cert-manager Certificate CRD: %w", err)
}

// CertificateRequest is one Certificate to create or update.
type CertificateRequest struct {
	Name       string
	Namespace  string
	SecretName string
	DNSNames   []string
	IssuerRef  cmmeta.IssuerReference
	PolicyName string
}

// Ensure creates or updates the Certificate, leaving it owned by owner.
func (w *CertificateWriter) Ensure(ctx context.Context, owner client.Object, req CertificateRequest) error {
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: req.Name, Namespace: req.Namespace},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, w.Client, cert, func() error {
		cert.Labels = mergeLabels(cert.Labels, map[string]string{
			v1alpha1.LabelManaged:     v1alpha1.LabelManagedValue,
			v1alpha1.LabelPolicy:      req.PolicyName,
			v1alpha1.LabelCertificate: req.Name,
		})

		cert.Spec.SecretName = req.SecretName
		cert.Spec.DNSNames = req.DNSNames
		cert.Spec.IssuerRef = req.IssuerRef

		// The label has to reach the *Secret*, not just the Certificate: the
		// manager's cache only watches labelled Secrets, so without this the
		// issued certificate would be invisible to the sync controller.
		cert.Spec.SecretTemplate = &cmapi.CertificateSecretTemplate{
			Labels: map[string]string{
				v1alpha1.LabelManaged:     v1alpha1.LabelManagedValue,
				v1alpha1.LabelPolicy:      req.PolicyName,
				v1alpha1.LabelCertificate: req.Name,
			},
		}

		// PKCS#8 is the only private key encoding Key Vault accepts. The
		// PKCS#12 encoder normalises it anyway, but asking cert-manager for it
		// directly keeps the Secret usable by anything else that reads it.
		cert.Spec.PrivateKey = &cmapi.CertificatePrivateKey{
			Encoding:       cmapi.PKCS8,
			RotationPolicy: cmapi.RotationPolicyAlways,
		}

		// Bound the CertificateRequest history so renewals do not accumulate.
		limit := int32(1)
		cert.Spec.RevisionHistoryLimit = &limit

		// A cluster-scoped owner of a namespaced dependent is permitted, so
		// deleting the policy garbage-collects the certificates it generated.
		return controllerutil.SetControllerReference(owner, cert, w.Client.Scheme())
	})
	if err != nil {
		return fmt.Errorf("ensuring certificate %s/%s: %w", req.Namespace, req.Name, err)
	}
	return nil
}

func mergeLabels(existing, additions map[string]string) map[string]string {
	if existing == nil {
		existing = map[string]string{}
	}
	for key, value := range additions {
		existing[key] = value
	}
	return existing
}
