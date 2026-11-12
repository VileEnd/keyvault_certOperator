package domain_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

// seedPair builds one valid certificate and key for the fuzzer to mutate. It
// uses the standard library directly because the testutil helpers want a
// *testing.T, and seeds are added before any exists.
func seedPair(f *testing.F) (certPEM, keyPEM []byte) {
	f.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"*.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		f.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		f.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// A Secret's contents are whatever someone put there, so the parser must never
// panic on them, and anything it accepts must be usable by everything after it.
func FuzzParseBundle(f *testing.F) {
	certPEM, keyPEM := seedPair(f)
	f.Add(certPEM, keyPEM)
	f.Add(keyPEM, certPEM)
	f.Add(append(append([]byte{}, certPEM...), certPEM...), keyPEM)
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), keyPEM)
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, cert, key []byte) {
		bundle, err := domain.ParseBundle(cert, key)
		if err != nil {
			return
		}
		if bundle.Leaf == nil || bundle.PrivateKey == nil {
			t.Fatal("ParseBundle returned no error and an incomplete bundle")
		}
		// These run on every accepted bundle in production.
		_ = bundle.ThumbprintHex()
		_ = bundle.ChainDigest()
		_ = bundle.SerialHex()
		_ = bundle.Validate(time.Now())
	})
}

// The derived name goes straight into a Key Vault URL and a Kubernetes object
// name, so whatever a hostname contains, the result is valid or an error.
func FuzzDeriveVaultCertificateName(f *testing.F) {
	for _, seed := range []string{"*.example.com", "example.com", "1.example.com", "", "*.", "a..b", "ÄÖ.example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, host string) {
		name, err := domain.DeriveVaultCertificateName(host)
		if err != nil {
			return
		}
		if err := domain.ValidateVaultCertificateName(name); err != nil {
			t.Fatalf("derived %q from %q, which is not a valid name: %v", name, host, err)
		}
	})
}
