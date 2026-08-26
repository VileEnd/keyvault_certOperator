package kube_test

import (
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/kube"
)

var certificateGVK = schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"}

func certManagerScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("building scheme: %v", err)
	}
	if err := cmapi.AddToScheme(scheme); err != nil {
		t.Fatalf("adding cert-manager to scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding operator types to scheme: %v", err)
	}
	return scheme
}

func mapperWithCertificate(present bool) meta.RESTMapper {
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{certificateGVK.GroupVersion()})
	if present {
		mapper.Add(certificateGVK, meta.RESTScopeNamespace)
	}
	return mapper
}

func TestCertificateWriterAvailable(t *testing.T) {
	t.Parallel()
	// cert-manager's presence is probed on every reconcile rather than once at
	// startup, so installing it later does not require an operator restart. Its
	// absence must be reported as "not available", never as an error.
	tests := []struct {
		name    string
		present bool
		want    bool
	}{
		{"cert-manager installed", true, true},
		{"cert-manager absent", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := fake.NewClientBuilder().WithScheme(certManagerScheme(t)).Build()
			writer := kube.NewCertificateWriter(c, mapperWithCertificate(tc.present))

			got, err := writer.Available(t.Context())
			if err != nil {
				t.Fatalf("Available: %v", err)
			}
			if got != tc.want {
				t.Errorf("Available() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCertificateWriterEnsureCreatesACorrectCertificate(t *testing.T) {
	t.Parallel()
	scheme := certManagerScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	writer := kube.NewCertificateWriter(c, mapperWithCertificate(true))

	policy := &v1alpha1.WildcardCertificatePolicy{ObjectMeta: metav1.ObjectMeta{Name: "public", UID: "abc"}}

	err := writer.Ensure(t.Context(), policy, kube.CertificateRequest{
		Name:       "wildcard-x-com",
		Namespace:  "cert-system",
		SecretName: "wildcard-x-com-tls",
		DNSNames:   []string{"*.x.com", "x.com"},
		IssuerRef:  cmmeta.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
		PolicyName: "public",
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	var got cmapi.Certificate
	key := client.ObjectKey{Namespace: "cert-system", Name: "wildcard-x-com"}
	if err := c.Get(t.Context(), key, &got); err != nil {
		t.Fatalf("reading the created certificate: %v", err)
	}

	if got.Spec.SecretName != "wildcard-x-com-tls" {
		t.Errorf("secretName = %q", got.Spec.SecretName)
	}
	// Key Vault accepts only PKCS#8 private keys. The PKCS#12 encoder normalises
	// this anyway, but asking cert-manager directly keeps the Secret usable by
	// anything else that reads it.
	if got.Spec.PrivateKey == nil || got.Spec.PrivateKey.Encoding != cmapi.PKCS8 {
		t.Errorf("privateKey = %+v, want PKCS8 encoding", got.Spec.PrivateKey)
	}
	// cert-manager recommends against setting commonName on leaf certificates:
	// TLS clients ignore it when SANs are present, and it risks a CSR rejection
	// past 64 characters. The SANs alone identify the certificate.
	if got.Spec.CommonName != "" {
		t.Errorf("commonName = %q, want it left unset", got.Spec.CommonName)
	}
	// Without the label on the *Secret*, the issued certificate falls outside the
	// operator's label-scoped cache and is never synced.
	if got.Spec.SecretTemplate == nil ||
		got.Spec.SecretTemplate.Labels[v1alpha1.LabelManaged] != v1alpha1.LabelManagedValue {
		t.Errorf("secretTemplate = %+v, want the managed label", got.Spec.SecretTemplate)
	}
	if got.Spec.RevisionHistoryLimit == nil || *got.Spec.RevisionHistoryLimit != 1 {
		t.Errorf("revisionHistoryLimit = %v, want 1 so renewals do not accumulate", got.Spec.RevisionHistoryLimit)
	}
	// A cluster-scoped owner of a namespaced dependent is permitted, and is what
	// garbage-collects generated certificates when the policy is deleted.
	if len(got.OwnerReferences) != 1 || got.OwnerReferences[0].Name != "public" {
		t.Errorf("ownerReferences = %+v, want the policy as controller", got.OwnerReferences)
	}
}

func TestCertificateWriterEnsureIsIdempotentAndUpdatesSANs(t *testing.T) {
	t.Parallel()
	scheme := certManagerScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	writer := kube.NewCertificateWriter(c, mapperWithCertificate(true))
	policy := &v1alpha1.WildcardCertificatePolicy{ObjectMeta: metav1.ObjectMeta{Name: "public", UID: "abc"}}

	request := kube.CertificateRequest{
		Name:       "wildcard-x-com",
		Namespace:  "cert-system",
		SecretName: "wildcard-x-com-tls",
		DNSNames:   []string{"*.x.com"},
		IssuerRef:  cmmeta.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer"},
		PolicyName: "public",
	}

	// Reconciles run repeatedly, so a second Ensure over unchanged input must not
	// churn the resource.
	for range 3 {
		if err := writer.Ensure(t.Context(), policy, request); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
	}

	var list cmapi.CertificateList
	if err := c.List(t.Context(), &list); err != nil {
		t.Fatalf("listing certificates: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("certificates = %d, want 1", len(list.Items))
	}

	// A newly discovered hostname must widen the existing certificate rather
	// than create a second one.
	request.DNSNames = []string{"*.x.com", "x.com"}
	if err := writer.Ensure(t.Context(), policy, request); err != nil {
		t.Fatalf("Ensure after widening: %v", err)
	}

	var got cmapi.Certificate
	if err := c.Get(t.Context(), client.ObjectKey{Namespace: "cert-system", Name: "wildcard-x-com"}, &got); err != nil {
		t.Fatalf("re-reading the certificate: %v", err)
	}
	if len(got.Spec.DNSNames) != 2 {
		t.Errorf("dnsNames = %v, want both names", got.Spec.DNSNames)
	}
}
