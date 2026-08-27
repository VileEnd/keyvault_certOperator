// Package domain holds the pure core of the operator: certificate parsing and
// validation, wildcard planning, Key Vault naming, and the import decision.
//
// Nothing in this package may import Kubernetes or Azure libraries. Everything
// here is deterministic and unit-testable without a cluster or a cloud account.
package domain

import "errors"

var (
	// ErrNoCertificates means the certificate PEM contained no CERTIFICATE blocks.
	ErrNoCertificates = errors.New("no certificates found in PEM data")
	// ErrNoPrivateKey means the key PEM contained no parsable private key.
	ErrNoPrivateKey = errors.New("no private key found in PEM data")
	// ErrUnsupportedKey means the private key is of a type we cannot use.
	ErrUnsupportedKey = errors.New("unsupported private key type")
	// ErrKeyMismatch means no supplied certificate matches the private key.
	ErrKeyMismatch = errors.New("private key does not match any supplied certificate")
	// ErrExpired means the leaf certificate is past its NotAfter. Key Vault
	// rejects expired certificates on import, so we fail early with a clear error.
	ErrExpired = errors.New("certificate has expired")
	// ErrNotYetValid means the leaf certificate's NotBefore is in the future.
	ErrNotYetValid = errors.New("certificate is not yet valid")
	// ErrNoDNSNames means the leaf carries no DNS subject alternative names.
	ErrNoDNSNames = errors.New("certificate has no DNS subject alternative names")
	// ErrInvalidVaultName means a Key Vault object name is not acceptable to Azure.
	ErrInvalidVaultName = errors.New("invalid Key Vault certificate name")
	// ErrInvalidHost means a hostname could not be parsed.
	ErrInvalidHost = errors.New("invalid hostname")
	// ErrInvalidZone means a configured zone is unusable as an issuance boundary.
	ErrInvalidZone = errors.New("invalid zone")
	// ErrInvalidPKCS12Profile means the requested PKCS#12 profile is unknown.
	// It had been reported as ErrInvalidVaultName, which put "invalid Key Vault
	// certificate name" in front of an operator whose name was perfectly fine.
	ErrInvalidPKCS12Profile = errors.New("invalid PKCS#12 profile")
	// ErrVaultNotAllowed means the resource named a vault outside the operator's
	// allowlist. It is terminal: no amount of retrying makes a vault permitted.
	ErrVaultNotAllowed = errors.New("key vault is not in the operator's allowlist")
)
