package controller_test

import (
	"crypto/x509"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/testutil"
)

// decodePKCS12 unpacks what the operator sent to the vault, so tests can assert
// on the certificate that actually travelled rather than on their own inputs.
func decodePKCS12(req app.ImportRequest) (key any, leaf *x509.Certificate, chain []*x509.Certificate, err error) {
	return gopkcs12.DecodeChain(req.Blob, req.Password)
}

// newTLSSecret builds a labelled kubernetes.io/tls Secret. The label matters:
// the manager's cache only watches labelled Secrets, so an unlabelled one is
// invisible to the operator by design.
func newTLSSecret(t *testing.T, namespace, name string, leaf *testutil.Leaf) *corev1.Secret {
	t.Helper()
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{v1alpha1.LabelManaged: v1alpha1.LabelManagedValue},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       leaf.CertPEM(t),
			corev1.TLSPrivateKeyKey: leaf.KeyPEM(t, testutil.PKCS8),
		},
	}
}

func newNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}
