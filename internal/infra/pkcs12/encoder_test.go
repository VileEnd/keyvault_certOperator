package pkcs12_test

import (
	"testing"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/pkcs12"
	"github.com/VileEnd/keyvault_certOperator/internal/testutil"
)

func TestEncodeRoundTripsTheFullChain(t *testing.T) {
	t.Parallel()
	// Application Gateway requires the complete chain with the leaf topmost, and
	// names an incomplete chain as a leading cause of certificate failures. Every
	// profile must therefore preserve leaf and intermediates alike.
	profiles := []pkcs12.Profile{pkcs12.ProfileLegacy, pkcs12.ProfilePasswordless, pkcs12.ProfileModern}

	for _, profile := range profiles {
		t.Run(string(profile), func(t *testing.T) {
			t.Parallel()
			root := testutil.NewRootCA(t, "test root")
			inter := root.Intermediate(t, "test intermediate")
			leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com", "x.com"}}).
				WithChain(inter.Cert, root.Cert)

			bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
			if err != nil {
				t.Fatalf("ParseBundle: %v", err)
			}

			encoder, err := pkcs12.NewEncoder(profile)
			if err != nil {
				t.Fatalf("NewEncoder: %v", err)
			}
			blob, password, err := encoder.Encode(bundle)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}

			key, cert, caCerts, err := gopkcs12.DecodeChain(blob, password)
			if err != nil {
				t.Fatalf("DecodeChain: %v", err)
			}
			if key == nil {
				t.Error("private key missing; Application Gateway requires it")
			}
			if !cert.Equal(leaf.Cert) {
				t.Error("decoded certificate is not the leaf")
			}
			if len(caCerts) != 2 {
				t.Fatalf("chain = %d certificates, want the intermediate and the root", len(caCerts))
			}
		})
	}
}

func TestEncodeNormalisesPKCS1KeysToPKCS8(t *testing.T) {
	t.Parallel()
	// Key Vault accepts only PKCS#8 private keys. Certbot 3.1.0 and cert-manager
	// both emit PKCS#1, so this normalisation is what makes those sources work
	// at all. go-pkcs12 always marshals PKCS#8 inside the archive.
	root := testutil.NewRootCA(t, "test root")
	leaf := root.Issue(t, testutil.LeafOptions{
		DNSNames: []string{"*.x.com"},
		KeyType:  testutil.RSA2048,
	})

	bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS1))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	encoder, err := pkcs12.NewEncoder(pkcs12.ProfileLegacy)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	blob, password, err := encoder.Encode(bundle)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, _, _, err := gopkcs12.DecodeChain(blob, password); err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
}

func TestPasswordlessProfileUsesAnEmptyPassword(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	leaf := root.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com"}})
	bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	encoder, err := pkcs12.NewEncoder(pkcs12.ProfilePasswordless)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	_, password, err := encoder.Encode(bundle)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if password != "" {
		t.Errorf("password = %q, want empty -- the passwordless encoder requires it", password)
	}
}

func TestNewEncoder(t *testing.T) {
	t.Parallel()
	// An empty profile must default rather than fail, so the CRD field is optional.
	encoder, err := pkcs12.NewEncoder("")
	if err != nil {
		t.Fatalf("NewEncoder(\"\"): %v", err)
	}
	if encoder.ContentType() != app.ContentTypePKCS12 {
		t.Errorf("content type = %q, want %q", encoder.ContentType(), app.ContentTypePKCS12)
	}
	if _, err := pkcs12.NewEncoder("des3-but-fancy"); err == nil {
		t.Error("expected an error for an unknown profile")
	}
}
