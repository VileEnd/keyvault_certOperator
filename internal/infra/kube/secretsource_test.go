package kube_test

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
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
			// The sentinel is what keeps this out of the vault's bucket: the
			// Secret is what has to change, and Azure has not been touched.
			wantErr: domain.ErrInvalidSourceSecret,
			wantMsg: "want \"kubernetes.io/tls\"",
		},
		{
			name:    "missing tls.crt",
			secret:  newSecret(corev1.SecretTypeTLS, map[string][]byte{corev1.TLSPrivateKeyKey: leaf.KeyPEM(t, testutil.PKCS8)}),
			wantErr: domain.ErrInvalidSourceSecret,
			wantMsg: "has no tls.crt",
		},
		{
			name:    "missing tls.key",
			secret:  newSecret(corev1.SecretTypeTLS, map[string][]byte{corev1.TLSCertKey: leaf.CertPEM(t)}),
			wantErr: domain.ErrInvalidSourceSecret,
			wantMsg: "has no tls.key",
		},
		{
			name: "empty tls.crt",
			secret: newSecret(corev1.SecretTypeTLS, map[string][]byte{
				corev1.TLSCertKey:       {},
				corev1.TLSPrivateKeyKey: leaf.KeyPEM(t, testutil.PKCS8),
			}),
			wantErr: domain.ErrInvalidSourceSecret,
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

func TestSecretSourceExplainsACacheMiss(t *testing.T) {
	t.Parallel()
	// The operator's Secret cache is label-selected, so a miss is one of two
	// things that read identically in the status and need opposite fixes: the
	// Secret has not been issued yet, or it is there and unlabelled. Nothing
	// else can tell them apart -- an unlabelled Secret is never delivered to the
	// cache at all -- so the uncached probe is the only source of the answer.
	labelled := newSecret(corev1.SecretTypeTLS, nil)
	labelled.Labels = map[string]string{v1alpha1.LabelManaged: v1alpha1.LabelManagedValue}
	unlabelled := newSecret(corev1.SecretTypeTLS, nil)
	wrongValue := newSecret(corev1.SecretTypeTLS, nil)
	wrongValue.Labels = map[string]string{v1alpha1.LabelManaged: "false"}

	tests := []struct {
		name         string
		uncached     client.Reader
		wantNotFound bool
		wantMsg      string
	}{
		{
			// No probe wired: the two stay indistinguishable, and saying so is
			// better than guessing which one it is.
			name:         "no probe",
			uncached:     nil,
			wantNotFound: true,
			wantMsg:      "certsync.vileend.io/managed",
		},
		{
			name:         "absent everywhere",
			uncached:     fake.NewClientBuilder().WithScheme(testScheme(t)).Build(),
			wantNotFound: true,
		},
		{
			// The probe can be refused outright on a namespace-scoped install.
			name:         "probe fails",
			uncached:     failingReader{},
			wantNotFound: true,
		},
		{
			// Present and labelled means the informer has simply not caught up.
			// The watch event is already on its way, so this is still waiting.
			name:         "informer lag",
			uncached:     fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(labelled).Build(),
			wantNotFound: true,
		},
		{
			name:     "present but unlabelled",
			uncached: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(unlabelled).Build(),
			wantMsg:  "exists but is not labelled certsync.vileend.io/managed=true",
		},
		{
			name:     "labelled with the wrong value",
			uncached: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(wrongValue).Build(),
			wantMsg:  "exists but is not labelled certsync.vileend.io/managed=true",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// An empty cache is exactly what the label selector produces for a
			// Secret it does not select.
			cached := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
			source := kube.NewSecretSource(cached)
			if tc.uncached != nil {
				source = source.WithVisibilityProbe(tc.uncached)
			}

			_, err := source.Load(t.Context(), secretRef())
			if err == nil {
				t.Fatal("expected an error for a secret the cache does not hold")
			}
			if got := apierrors.IsNotFound(err); got != tc.wantNotFound {
				t.Errorf("apierrors.IsNotFound(%v) = %v, want %v", err, got, tc.wantNotFound)
			}
			// The two must not both be true: IsNotFound is checked first when the
			// condition is classified, so a visible-but-unlabelled Secret wrapping
			// a NotFound would still be reported as SourceNotFound.
			if got := errors.Is(err, domain.ErrSourceSecretNotVisible); got == tc.wantNotFound {
				t.Errorf("errors.Is(%v, ErrSourceSecretNotVisible) = %v, want %v", err, got, !tc.wantNotFound)
			}
			if tc.wantMsg != "" && !contains(err.Error(), tc.wantMsg) {
				t.Errorf("err = %q, want it to mention %q", err, tc.wantMsg)
			}
		})
	}
}

// failingReader stands in for an API server that refuses the probe, which is
// what a namespace-scoped install sees for a namespace it was not granted.
type failingReader struct{ client.Reader }

func (failingReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("secrets is forbidden")
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
