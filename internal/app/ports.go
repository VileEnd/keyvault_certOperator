// Package app holds the operator's use cases.
//
// It depends on the domain and on the interfaces declared here, and on nothing
// else. The interfaces are deliberately defined at the point of use rather than
// beside their implementations, so that infrastructure adapters can be swapped
// or faked without the core knowing they exist.
package app

import (
	"context"
	"strings"
	"time"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

// SecretRef identifies the Kubernetes Secret holding a certificate.
type SecretRef struct {
	Namespace string
	Name      string
}

func (r SecretRef) String() string { return r.Namespace + "/" + r.Name }

// VaultRef identifies one certificate object inside one Key Vault.
type VaultRef struct {
	// VaultURL is the vault's base URL, e.g. https://my-vault.vault.azure.net.
	VaultURL string
	// CertificateName is the Key Vault object name; see domain.ValidateVaultCertificateName.
	CertificateName string
}

// SecretIdentifier returns the *versionless* secret identifier for this
// certificate, which is the value an Application Gateway listener must be
// configured with.
//
// The path is /secrets/ rather than /certificates/ because Application Gateway
// reads the addressable secret behind the certificate. Omitting the version is
// what enables automatic rotation: a versioned URI pins the listener to one
// version forever and silently disables the four-hourly refresh.
func (r VaultRef) SecretIdentifier() string {
	return strings.TrimSuffix(r.VaultURL, "/") + "/secrets/" + r.CertificateName
}

// Key Vault tags stamped on every certificate this operator imports.
const (
	// TagManagedBy marks ownership so an operator-managed certificate is
	// distinguishable from one uploaded by hand.
	TagManagedBy = "managed-by"
	// TagManagedByValue is the value written to TagManagedBy.
	TagManagedByValue = "keyvault-certoperator"
	// TagSourceNamespace records the namespace of the originating Secret.
	TagSourceNamespace = "source-namespace"
	// TagSourceSecret records the name of the originating Secret.
	TagSourceSecret = "source-secret"
	// TagChainDigest carries the digest of the leaf plus its full chain.
	//
	// Key Vault's own X509Thumbprint covers the leaf only, so without this tag a
	// CA intermediate rotation would leave a stale chain in the vault forever.
	// Reading the stored chain back instead would require secrets/getSecret,
	// which this operator deliberately never requests.
	TagChainDigest = "chain-sha256"
	// TagNotAfter records the leaf's expiry in RFC3339, for querying in Azure.
	TagNotAfter = "not-after"
	// TagSerial records the leaf's serial number in hex.
	TagSerial = "serial"
)

// ContentTypePKCS12 is the Key Vault content type for a PFX import.
//
// PKCS#12 is used rather than PEM because Microsoft's documentation contradicts
// itself on Application Gateway's PEM support, while every source agrees on PFX.
const ContentTypePKCS12 = "application/x-pkcs12"

// CertificateSource loads a certificate bundle out of the cluster.
type CertificateSource interface {
	Load(ctx context.Context, ref SecretRef) (*domain.Bundle, error)
}

// ImportRequest is one certificate import.
type ImportRequest struct {
	// Blob is the PKCS#12 payload, unencoded.
	Blob []byte
	// Password protects Blob. Key Vault discards it on import and re-encodes the
	// certificate, so it never needs to be stored anywhere.
	Password string
	// ContentType tells Key Vault how to read Blob.
	ContentType string
	// Tags are stamped on the imported version.
	Tags map[string]string
}

// ImportResult reports what Key Vault created.
type ImportResult struct {
	// Version is the new version identifier. Every import creates one, and they
	// cannot be deleted, which is why Decide runs first.
	Version string
	// Thumbprint is the SHA-1 of the imported leaf, as returned by Key Vault.
	Thumbprint []byte
}

// VaultRepository is the Key Vault side of the sync.
type VaultRepository interface {
	// Snapshot reports what the vault currently holds. A missing certificate is
	// not an error: it returns a snapshot with Exists false.
	Snapshot(ctx context.Context, ref VaultRef) (domain.VaultSnapshot, error)
	// Import uploads a new version of the certificate.
	Import(ctx context.Context, ref VaultRef, req ImportRequest) (ImportResult, error)
}

// Encoder turns a bundle into the payload Key Vault will accept.
type Encoder interface {
	// Encode returns the encoded blob and the password protecting it.
	Encode(bundle *domain.Bundle) (blob []byte, password string, err error)
	// ContentType is the Key Vault content type for the blobs this encoder produces.
	ContentType() string
}

// HostSource enumerates the hostnames routed by the cluster.
type HostSource interface {
	Hosts(ctx context.Context) ([]string, error)
}

// Clock exists so that expiry logic is testable without waiting.
type Clock interface {
	Now() time.Time
}

// RealClock is the production Clock.
type RealClock struct{}

// Now returns the current time.
func (RealClock) Now() time.Time { return time.Now() }
