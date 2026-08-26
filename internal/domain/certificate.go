package domain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- SHA-1 here is an identifier (Azure's x5t), not a security primitive.
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"
)

// Bundle is a parsed, validated TLS certificate together with its private key
// and issuing chain. Chain holds the intermediates (and optionally the root)
// ordered from the leaf outwards; it never contains the leaf itself.
type Bundle struct {
	Leaf       *x509.Certificate
	Chain      []*x509.Certificate
	PrivateKey crypto.PrivateKey
}

// ParseBundle reads a certificate PEM (typically a Secret's tls.crt) and a key
// PEM (tls.key) into a Bundle.
//
// It is deliberately permissive about its input, because the producers are not:
//
//   - "kubectl create secret tls" validates almost nothing, so the certificate
//     order in tls.crt cannot be trusted. We identify the leaf by matching public
//     keys and then order the chain ourselves.
//   - Private keys arrive in three encodings. Certbot <=3.0.1 and >=3.2.0 emit
//     PKCS#8, but Certbot 3.1.0 regressed to PKCS#1, and cert-manager defaults to
//     PKCS#1 unless privateKey.encoding is set to PKCS8. We accept all of them.
//   - Both RSA and ECDSA appear in practice; Certbot has defaulted to ECDSA
//     P-256 since 2.0.
func ParseBundle(certPEM, keyPEM []byte) (*Bundle, error) {
	certs, err := parseCertificates(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}

	leaf, rest, err := selectLeaf(certs, key)
	if err != nil {
		return nil, err
	}

	return &Bundle{
		Leaf:       leaf,
		Chain:      orderChain(leaf, rest),
		PrivateKey: key,
	}, nil
}

// parseCertificates decodes every CERTIFICATE block in a PEM blob, ignoring any
// other block types so that a concatenated key+cert file still parses.
func parseCertificates(certPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, ErrNoCertificates
	}
	return certs, nil
}

// ParsePrivateKey accepts PKCS#8 ("PRIVATE KEY"), PKCS#1 ("RSA PRIVATE KEY")
// and SEC1 ("EC PRIVATE KEY") encodings. Each parser is tried regardless of the
// PEM header, because some tools mislabel the block.
func ParsePrivateKey(keyPEM []byte) (crypto.PrivateKey, error) {
	rest := keyPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			continue
		}
		if key, ok := tryParseKey(block.Bytes); ok {
			switch key.(type) {
			case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
				return key, nil
			default:
				return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, key)
			}
		}
	}
	return nil, ErrNoPrivateKey
}

func tryParseKey(der []byte) (crypto.PrivateKey, bool) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, true
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, true
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, true
	}
	return nil, false
}

// selectLeaf finds the certificate whose public key matches the private key.
// That, rather than input position, is what makes a certificate the leaf.
func selectLeaf(certs []*x509.Certificate, key crypto.PrivateKey) (*x509.Certificate, []*x509.Certificate, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, ErrUnsupportedKey
	}
	pub := signer.Public()

	for i, cert := range certs {
		if publicKeysEqual(cert.PublicKey, pub) {
			rest := make([]*x509.Certificate, 0, len(certs)-1)
			rest = append(rest, certs[:i]...)
			rest = append(rest, certs[i+1:]...)
			return cert, rest, nil
		}
	}
	return nil, nil, ErrKeyMismatch
}

// publicKeysEqual compares two public keys. Every stdlib key type implements
// Equal(crypto.PublicKey) bool.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	eq, ok := a.(equaler)
	if !ok {
		return false
	}
	return eq.Equal(b)
}

// Thumbprint returns the SHA-1 digest of the leaf's DER bytes.
//
// This is the same value Azure Key Vault exposes as X509Thumbprint (x5t), which
// is what makes a single GetCertificate enough to decide whether an import is
// needed. It identifies the leaf only -- see ChainDigest.
func (b *Bundle) Thumbprint() []byte {
	sum := sha1.Sum(b.Leaf.Raw) // #nosec G401 -- identifier, not a security primitive.
	return sum[:]
}

// ThumbprintHex returns Thumbprint as a lowercase hex string, for status fields.
func (b *Bundle) ThumbprintHex() string {
	return hex.EncodeToString(b.Thumbprint())
}

// ChainDigest returns a SHA-256 over the leaf and the full ordered chain.
//
// The leaf thumbprint alone is not sufficient to detect drift: Let's Encrypt has
// rotated its intermediates several times (R3 to R10/R11, E5/E6), and such a
// rotation leaves the leaf byte-identical while the stored chain goes stale. We
// therefore stamp this digest as a Key Vault tag and compare it too. Tags come
// back free on GetCertificate, whereas reading the stored chain itself would
// require secrets/getSecret -- a permission we deliberately never request.
func (b *Bundle) ChainDigest() string {
	h := sha256.New()
	h.Write(b.Leaf.Raw)
	for _, cert := range b.Chain {
		h.Write(cert.Raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// DNSNames returns the leaf's DNS subject alternative names.
func (b *Bundle) DNSNames() []string {
	return b.Leaf.DNSNames
}

// NotAfter returns the leaf's expiry.
func (b *Bundle) NotAfter() time.Time { return b.Leaf.NotAfter }

// NotBefore returns the start of the leaf's validity window.
func (b *Bundle) NotBefore() time.Time { return b.Leaf.NotBefore }

// SerialHex returns the leaf's serial number in hex, for tagging and status.
func (b *Bundle) SerialHex() string {
	if b.Leaf.SerialNumber == nil {
		return ""
	}
	return hex.EncodeToString(b.Leaf.SerialNumber.Bytes())
}

// Validate checks the bundle is fit to import at the given time.
//
// Expiry is checked here rather than left to Azure because Key Vault rejects
// expired certificates with an opaque 400; failing locally lets us surface a
// precise condition instead.
func (b *Bundle) Validate(now time.Time) error {
	if now.After(b.Leaf.NotAfter) {
		return fmt.Errorf("%w at %s", ErrExpired, b.Leaf.NotAfter.Format(time.RFC3339))
	}
	if now.Before(b.Leaf.NotBefore) {
		return fmt.Errorf("%w until %s", ErrNotYetValid, b.Leaf.NotBefore.Format(time.RFC3339))
	}
	if len(b.Leaf.DNSNames) == 0 {
		return ErrNoDNSNames
	}
	return nil
}
