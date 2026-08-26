package domain_test

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- test asserts the identifier Azure uses.
	"errors"
	"testing"
	"time"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/testutil"
)

func TestParseBundleAcceptsEveryKeyEncoding(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "test intermediate")

	// Certbot <=3.0.1 and >=3.2.0 emit PKCS#8, Certbot 3.1.0 emitted PKCS#1, and
	// cert-manager defaults to PKCS#1. All three must parse.
	tests := []struct {
		name     string
		keyType  testutil.KeyType
		encoding testutil.KeyEncoding
	}{
		{"RSA PKCS#8", testutil.RSA2048, testutil.PKCS8},
		{"RSA PKCS#1", testutil.RSA2048, testutil.PKCS1},
		{"ECDSA PKCS#8", testutil.ECDSAP256, testutil.PKCS8},
		{"ECDSA SEC1", testutil.ECDSAP256, testutil.SEC1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			leaf := inter.Issue(t, testutil.LeafOptions{
				DNSNames: []string{"*.example.com", "example.com"},
				KeyType:  tc.keyType,
			})

			bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, tc.encoding))
			if err != nil {
				t.Fatalf("ParseBundle: %v", err)
			}
			if !bundle.Leaf.Equal(leaf.Cert) {
				t.Error("wrong certificate selected as leaf")
			}
			if len(bundle.Chain) != 1 || !bundle.Chain[0].Equal(inter.Cert) {
				t.Errorf("chain = %d certs, want the intermediate", len(bundle.Chain))
			}
		})
	}
}

func TestParseBundleIdentifiesLeafRegardlessOfOrder(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "test intermediate")
	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.example.com"}}).
		WithChain(inter.Cert, root.Cert)

	// "kubectl create secret tls" performs almost no validation, so the order in
	// tls.crt cannot be trusted. The leaf is the certificate matching the key.
	for _, tc := range []struct {
		name string
		pem  []byte
	}{
		{"leaf first", leaf.CertPEM(t)},
		{"leaf last", leaf.CertPEMReversed(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bundle, err := domain.ParseBundle(tc.pem, leaf.KeyPEM(t, testutil.PKCS8))
			if err != nil {
				t.Fatalf("ParseBundle: %v", err)
			}
			if !bundle.Leaf.Equal(leaf.Cert) {
				t.Fatal("leaf not identified by key match")
			}
			// Application Gateway needs leaf then intermediate then root.
			if len(bundle.Chain) != 2 {
				t.Fatalf("chain = %d certs, want 2", len(bundle.Chain))
			}
			if !bundle.Chain[0].Equal(inter.Cert) {
				t.Error("intermediate should come first in the chain")
			}
			if !bundle.Chain[1].Equal(root.Cert) {
				t.Error("root should come last in the chain")
			}
		})
	}
}

func TestParseBundleErrors(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	leafA := root.Issue(t, testutil.LeafOptions{DNSNames: []string{"a.example.com"}})
	leafB := root.Issue(t, testutil.LeafOptions{DNSNames: []string{"b.example.com"}})

	tests := []struct {
		name    string
		certPEM []byte
		keyPEM  []byte
		want    error
	}{
		{"no certificates", []byte("not a pem"), leafA.KeyPEM(t, testutil.PKCS8), domain.ErrNoCertificates},
		{"no private key", leafA.CertPEM(t), []byte("not a pem"), domain.ErrNoPrivateKey},
		{"key does not match", leafA.CertPEM(t), leafB.KeyPEM(t, testutil.PKCS8), domain.ErrKeyMismatch},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParseBundle(tc.certPEM, tc.keyPEM); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestThumbprintMatchesAzureX5T(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	leaf := root.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.example.com"}})

	bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	// Key Vault's X509Thumbprint is the SHA-1 of the leaf DER. Matching it
	// exactly is what lets one GetCertificate decide whether to import.
	want := sha1.Sum(leaf.Cert.Raw) // #nosec G401 -- identifier, not a security primitive.
	if !bytes.Equal(bundle.Thumbprint(), want[:]) {
		t.Errorf("Thumbprint() = %x, want %x", bundle.Thumbprint(), want)
	}
}

func TestChainDigestDetectsIntermediateRotation(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "intermediate R10")
	rotated := root.Intermediate(t, "intermediate R11")

	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.example.com"}})

	original, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	// Same leaf, different chain: exactly what a CA intermediate rotation looks
	// like. The thumbprint cannot see it, so the chain digest must.
	reissued, err := domain.ParseBundle(
		append(leaf.LeafOnlyPEM(t), testutil.EncodeCertPEM(t, rotated.Cert)...),
		leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	if !bytes.Equal(original.Thumbprint(), reissued.Thumbprint()) {
		t.Fatal("precondition failed: leaf thumbprints should be identical")
	}
	if original.ChainDigest() == reissued.ChainDigest() {
		t.Error("ChainDigest() did not change when the intermediate rotated")
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	now := time.Now()

	tests := []struct {
		name string
		opts testutil.LeafOptions
		want error
	}{
		{
			name: "valid",
			opts: testutil.LeafOptions{DNSNames: []string{"*.example.com"}},
		},
		{
			// Key Vault rejects expired certificates with an opaque 400, so we
			// fail locally with something a user can act on.
			name: "expired",
			opts: testutil.LeafOptions{
				DNSNames:  []string{"*.example.com"},
				NotBefore: now.Add(-48 * time.Hour),
				NotAfter:  now.Add(-time.Hour),
			},
			want: domain.ErrExpired,
		},
		{
			name: "not yet valid",
			opts: testutil.LeafOptions{
				DNSNames:  []string{"*.example.com"},
				NotBefore: now.Add(time.Hour),
				NotAfter:  now.Add(48 * time.Hour),
			},
			want: domain.ErrNotYetValid,
		},
		{
			name: "no DNS names",
			opts: testutil.LeafOptions{},
			want: domain.ErrNoDNSNames,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			leaf := root.Issue(t, tc.opts)
			bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
			if err != nil {
				t.Fatalf("ParseBundle: %v", err)
			}
			if err := bundle.Validate(now); !errors.Is(err, tc.want) {
				t.Errorf("Validate() = %v, want %v", err, tc.want)
			}
		})
	}
}
