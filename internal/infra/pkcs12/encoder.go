// Package pkcs12 encodes a certificate bundle into the PFX payload Key Vault
// accepts on import.
package pkcs12

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Profile selects the PKCS#12 algorithm set.
//
// Which profile is safe is a compatibility question, not a security one. Key
// Vault discards the password on import and re-encodes the certificate, so the
// PFX this operator produces exists only in memory and only for the duration of
// one TLS call to Azure. What Application Gateway eventually fetches is Key
// Vault's own output, not ours. The profile therefore only has to be readable by
// Key Vault itself.
type Profile string

const (
	// ProfileLegacy uses 3DES with SHA-1, the same parameters as OpenSSL's
	// -descert. Azure's Application Gateway troubleshooting guidance explicitly
	// asks for TripleDES-SHA1 and warns that some Azure services cannot parse
	// AES-256-CBC, which makes this the safest default.
	ProfileLegacy Profile = "legacy"
	// ProfilePasswordless produces an unencrypted PFX. Key Vault accepts these --
	// the import API documents the password as optional -- and it is what
	// External Secrets Operator ships for this same purpose.
	ProfilePasswordless Profile = "passwordless"
	// ProfileModern uses PBES2 with AES-256-CBC and HMAC-SHA-256. Preferred if
	// your vault accepts it; verify against a real Application Gateway first.
	ProfileModern Profile = "modern"
)

// Encoder implements app.Encoder.
type Encoder struct {
	profile Profile
}

// NewEncoder returns an Encoder for the named profile. An empty profile
// defaults to ProfileLegacy.
func NewEncoder(profile Profile) (*Encoder, error) {
	switch profile {
	case "":
		return &Encoder{profile: ProfileLegacy}, nil
	case ProfileLegacy, ProfilePasswordless, ProfileModern:
		return &Encoder{profile: profile}, nil
	default:
		return nil, fmt.Errorf("unknown pkcs12 profile %q", profile)
	}
}

// ContentType reports the Key Vault content type for the blobs we produce.
func (e *Encoder) ContentType() string { return app.ContentTypePKCS12 }

// Encode builds a PKCS#12 archive containing the private key, the leaf, and the
// full issuing chain.
//
// The argument order matters: the leaf is passed as the certificate and the
// intermediates as caCerts, which is the exact equivalent of
// "openssl pkcs12 -export -in <leaf> -certfile <chain>". Application Gateway
// requires the complete chain with the leaf topmost, and lists an incomplete
// chain among the leading causes of certificate failures.
func (e *Encoder) Encode(bundle *domain.Bundle) ([]byte, string, error) {
	if bundle == nil {
		return nil, "", domain.ErrNoCertificates
	}

	encoder, password, err := e.settings()
	if err != nil {
		return nil, "", err
	}

	blob, err := encoder.Encode(bundle.PrivateKey, bundle.Leaf, bundle.Chain, password)
	if err != nil {
		return nil, "", fmt.Errorf("encoding pkcs#12 (%s profile): %w", e.profile, err)
	}
	return blob, password, nil
}

func (e *Encoder) settings() (*pkcs12.Encoder, string, error) {
	switch e.profile {
	case ProfilePasswordless:
		// This encoder applies no encryption and no MAC, and requires an empty
		// password.
		return pkcs12.Passwordless, "", nil
	case ProfileModern:
		// Modern2023 uses real encryption, so a low-entropy password would be a
		// genuine weakness; generate one rather than reusing "changeit".
		password, err := randomPassword()
		if err != nil {
			return nil, "", err
		}
		return pkcs12.Modern2023, password, nil
	default:
		// go-pkcs12 recommends the well-known password with its weak encoders,
		// precisely because the password is not what protects the file. Here
		// nothing needs protecting: Key Vault strips it immediately.
		return pkcs12.LegacyDES, pkcs12.DefaultPassword, nil
	}
}

func randomPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating pkcs#12 password: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
