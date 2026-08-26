// Package testutil builds throwaway certificate chains for tests.
//
// It exists so that domain, application and infrastructure tests can exercise
// real x509 material -- RSA and ECDSA, every private-key encoding, wildcards,
// expired certificates, broken chains -- without fixtures on disk or a network.
package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// KeyType selects the algorithm for a generated key.
type KeyType int

const (
	// RSA2048 mirrors Certbot's pre-2.0 default and cert-manager's common setting.
	RSA2048 KeyType = iota
	// ECDSAP256 mirrors Certbot's default since 2.0.
	ECDSAP256
)

// KeyEncoding selects how a private key is marshalled to PEM.
type KeyEncoding int

const (
	// PKCS8 is what Key Vault requires and what Certbot emits outside 3.1.0.
	PKCS8 KeyEncoding = iota
	// PKCS1 is what Certbot 3.1.0 regressed to and cert-manager defaults to.
	PKCS1
	// SEC1 is the "EC PRIVATE KEY" encoding.
	SEC1
)

// Authority is a signing certificate plus its key. A root and an intermediate
// are both represented by this type.
type Authority struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// Leaf is an issued end-entity certificate with its key and issuing chain.
type Leaf struct {
	Cert  *x509.Certificate
	Key   crypto.Signer
	Chain []*x509.Certificate // intermediates, leaf-adjacent first
}

// LeafOptions customises an issued certificate.
type LeafOptions struct {
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
	KeyType   KeyType
}

// NewRootCA creates a self-signed certificate authority.
func NewRootCA(t *testing.T, commonName string) *Authority {
	t.Helper()
	key := newKey(t, ECDSAP256)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return &Authority{Cert: signCert(t, tmpl, tmpl, key.Public(), key), Key: key}
}

// Intermediate issues a subordinate CA under a.
func (a *Authority) Intermediate(t *testing.T, commonName string) *Authority {
	t.Helper()
	key := newKey(t, ECDSAP256)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return &Authority{Cert: signCert(t, tmpl, a.Cert, key.Public(), a.Key), Key: key}
}

// Issue creates an end-entity certificate signed by a.
func (a *Authority) Issue(t *testing.T, opts LeafOptions) *Leaf {
	t.Helper()
	if opts.NotBefore.IsZero() {
		opts.NotBefore = time.Now().Add(-time.Hour)
	}
	if opts.NotAfter.IsZero() {
		opts.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	key := newKey(t, opts.KeyType)
	cn := ""
	if len(opts.DNSNames) > 0 {
		cn = opts.DNSNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              opts.DNSNames,
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return &Leaf{Cert: signCert(t, tmpl, a.Cert, key.Public(), a.Key), Key: key, Chain: []*x509.Certificate{a.Cert}}
}

// WithChain replaces the leaf's recorded issuing chain, for tests that need a
// specific chain (for example an intermediate plus a root).
func (l *Leaf) WithChain(chain ...*x509.Certificate) *Leaf {
	l.Chain = chain
	return l
}

// CertPEM returns the leaf followed by its chain, the layout of a Certbot
// fullchain.pem and of a cert-manager tls.crt.
func (l *Leaf) CertPEM(t *testing.T) []byte {
	t.Helper()
	out := EncodeCertPEM(t, l.Cert)
	for _, cert := range l.Chain {
		out = append(out, EncodeCertPEM(t, cert)...)
	}
	return out
}

// CertPEMReversed returns the chain with the leaf last, which is what a
// carelessly assembled Secret looks like.
func (l *Leaf) CertPEMReversed(t *testing.T) []byte {
	t.Helper()
	var out []byte
	for i := len(l.Chain) - 1; i >= 0; i-- {
		out = append(out, EncodeCertPEM(t, l.Chain[i])...)
	}
	return append(out, EncodeCertPEM(t, l.Cert)...)
}

// LeafOnlyPEM returns just the leaf, with no intermediates.
func (l *Leaf) LeafOnlyPEM(t *testing.T) []byte {
	t.Helper()
	return EncodeCertPEM(t, l.Cert)
}

// KeyPEM marshals the leaf's private key in the requested encoding.
func (l *Leaf) KeyPEM(t *testing.T, enc KeyEncoding) []byte {
	t.Helper()
	return EncodeKeyPEM(t, l.Key, enc)
}

// EncodeCertPEM PEM-encodes a certificate.
func EncodeCertPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// EncodeKeyPEM PEM-encodes a private key in the requested encoding.
func EncodeKeyPEM(t *testing.T, key crypto.Signer, enc KeyEncoding) []byte {
	t.Helper()
	switch enc {
	case PKCS1:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("PKCS#1 encoding requires an RSA key, got %T", key)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	case SEC1:
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("SEC1 encoding requires an ECDSA key, got %T", key)
		}
		der, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			t.Fatalf("marshalling SEC1 key: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	default:
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshalling PKCS#8 key: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
}

func newKey(t *testing.T, kt KeyType) crypto.Signer {
	t.Helper()
	if kt == RSA2048 {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generating RSA key: %v", err)
		}
		return key
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	return key
}

func signCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing created certificate: %v", err)
	}
	return cert
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}
	return n
}
