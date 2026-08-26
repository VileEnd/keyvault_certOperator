package kube_test

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/kube"
	"github.com/VileEnd/keyvault_certOperator/internal/testutil"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("building scheme: %v", err)
	}
	return scheme
}

func secretRef() app.SecretRef {
	return app.SecretRef{Namespace: "certs", Name: "wildcard-tls"}
}

func newSecret(secretType corev1.SecretType, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "wildcard-tls", Namespace: "certs"},
		Type:       secretType,
		Data:       data,
	}
}

func TestSecretSourceLoadsAValidTLSSecret(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "test intermediate")
	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com", "x.com"}})

	client := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(newSecret(corev1.SecretTypeTLS, map[string][]byte{
			corev1.TLSCertKey:       leaf.CertPEM(t),
			corev1.TLSPrivateKeyKey: leaf.KeyPEM(t, testutil.PKCS8),
		})).Build()

	bundle, err := kube.NewSecretSource(client).Load(t.Context(), secretRef())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bundle.Leaf.Equal(leaf.Cert) {
		t.Error("wrong certificate selected as the leaf")
	}
	if len(bundle.Chain) != 1 {
		t.Errorf("chain = %d certificates, want the intermediate", len(bundle.Chain))
	}
}

func TestSecretSourceRejectsUnusableSecrets(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	leaf := root.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com"}})

	tests := []struct {
		name    string
		secret  *corev1.Secret
		wantErr error
		wantMsg string
	}{
		{
			// An Opaque Secret holding PEM is a common mistake; naming the type
			// mismatch is far more useful than a parse error further down.
			name: "wrong secret type",
			secret: newSecret(corev1.SecretTypeOpaque, map[string][]byte{
				corev1.TLSCertKey:       leaf.CertPEM(t),
				corev1.TLSPrivateKeyKey: leaf.KeyPEM(t, testutil.PKCS8),
			}),
			wantMsg: "want \"kubernetes.io/tls\"",
		},
		{
			name:    "missing tls.crt",
			secret:  newSecret(corev1.SecretTypeTLS, map[string][]byte{corev1.TLSPrivateKeyKey: leaf.KeyPEM(t, testutil.PKCS8)}),
			wantMsg: "has no tls.crt",
		},
		{
			name:    "missing tls.key",
			secret:  newSecret(corev1.SecretTypeTLS, map[string][]byte{corev1.TLSCertKey: leaf.CertPEM(t)}),
			wantMsg: "has no tls.key",
		},
		{
			name: "empty tls.crt",
			secret: newSecret(corev1.SecretTypeTLS, map[string][]byte{
				corev1.TLSCertKey:       {},
				corev1.TLSPrivateKeyKey: leaf.KeyPEM(t, testutil.PKCS8),
			}),
			wantMsg: "has no tls.crt",
		},
		{
			name: "unparsable certificate",
			secret: newSecret(corev1.SecretTypeTLS, map[string][]byte{
				corev1.TLSCertKey:       []byte("not a pem"),
				corev1.TLSPrivateKeyKey: leaf.KeyPEM(t, testutil.PKCS8),
			}),
			wantErr: domain.ErrNoCertificates,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tc.secret).Build()

			_, err := kube.NewSecretSource(client).Load(t.Context(), secretRef())
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want it to wrap %v", err, tc.wantErr)
			}
			if tc.wantMsg != "" && !contains(err.Error(), tc.wantMsg) {
				t.Errorf("err = %q, want it to mention %q", err, tc.wantMsg)
			}
		})
	}
}

func TestSecretSourceKeepsNotFoundDetectable(t *testing.T) {
	t.Parallel()
	// The controller distinguishes "cert-manager has not issued this yet" from a
	// real failure by calling apierrors.IsNotFound on the returned error, so the
	// wrapping here must preserve that.
	client := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()

	_, err := kube.NewSecretSource(client).Load(t.Context(), secretRef())
	if err == nil {
		t.Fatal("expected an error for a missing secret")
	}
	if !apierrors.IsNotFound(err) {
		t.Errorf("apierrors.IsNotFound(%v) = false, want true", err)
	}
	// The message should point at the most common cause of an "invisible" Secret.
	if !contains(err.Error(), "certsync.vileend.io/managed") {
		t.Errorf("err = %q, want it to mention the managed label", err)
	}
}

func TestSecretSourceDoesNotLeakKeyMaterialIntoErrors(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	leafA := root.Issue(t, testutil.LeafOptions{DNSNames: []string{"a.x.com"}})
	leafB := root.Issue(t, testutil.LeafOptions{DNSNames: []string{"b.x.com"}})

	// A mismatched pair produces an error naming the Secret and the failure mode.
	// It must never quote the PEM: these errors reach logs, events and status.
	client := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(newSecret(corev1.SecretTypeTLS, map[string][]byte{
			corev1.TLSCertKey:       leafA.CertPEM(t),
			corev1.TLSPrivateKeyKey: leafB.KeyPEM(t, testutil.PKCS8),
		})).Build()

	_, err := kube.NewSecretSource(client).Load(t.Context(), secretRef())
	if !errors.Is(err, domain.ErrKeyMismatch) {
		t.Fatalf("err = %v, want ErrKeyMismatch", err)
	}
	for _, forbidden := range []string{"BEGIN", "PRIVATE KEY", "CERTIFICATE"} {
		if contains(err.Error(), forbidden) {
			t.Errorf("error message contains %q; it must never carry key or certificate material: %q",
				forbidden, err)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		})()
}
