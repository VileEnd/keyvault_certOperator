package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// MaxVaultNameLength is Azure's ceiling for a Key Vault object name.
const MaxVaultNameLength = 127

// WildcardPrefix replaces the "*." of a wildcard DNS name, which Key Vault
// names may not contain.
const WildcardPrefix = "wildcard-"

// ValidateVaultCertificateName reports whether name is acceptable to Azure Key
// Vault. Azure's own constraint is 1-127 characters of [0-9a-zA-Z-]; we
// additionally require a leading letter, which keeps the name valid for every
// Key Vault object type and avoids surprises in the portal.
func ValidateVaultCertificateName(name string) error {
	if name == "" || len(name) > MaxVaultNameLength {
		return fmt.Errorf("%w: %q must be 1-%d characters", ErrInvalidVaultName, name, MaxVaultNameLength)
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r == '-', r >= '0' && r <= '9':
			if i == 0 {
				return fmt.Errorf("%w: %q must start with a letter", ErrInvalidVaultName, name)
			}
		default:
			return fmt.Errorf("%w: %q may only contain letters, digits and hyphens", ErrInvalidVaultName, name)
		}
	}
	return nil
}

// DeriveVaultCertificateName turns a DNS name into a valid Key Vault
// certificate name, e.g. "*.example.com" becomes "wildcard-example-com".
//
// This mapping is intentionally only a *default*. It is not injective --
// "foo.example.com" and "foo-example.com" both collapse to "foo-example-com" --
// so the name is exposed as a settable CRD field and echoed in status. Callers
// that generate names in bulk should use DisambiguateVaultName to resolve
// collisions rather than relying on this being unique.
func DeriveVaultCertificateName(dnsName string) (string, error) {
	host := NormalizeHost(dnsName)
	if host == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidHost)
	}

	name := host
	if wildcard, ok := strings.CutPrefix(name, "*."); ok {
		name = WildcardPrefix + wildcard
	}
	name = strings.ReplaceAll(name, ".", "-")

	// A leading digit is legal for Azure certificates but not for every object
	// type; prefixing keeps one derivation rule usable everywhere.
	if name != "" && !isASCIILetter(rune(name[0])) {
		name = "cert-" + name
	}
	if len(name) > MaxVaultNameLength {
		name = truncateWithDigest(name, host)
	}

	if err := ValidateVaultCertificateName(name); err != nil {
		return "", fmt.Errorf("deriving name from %q: %w", dnsName, err)
	}
	return name, nil
}

// DisambiguateVaultName appends a short digest of seed to name, for use when
// two different DNS names derive the same Key Vault name.
func DisambiguateVaultName(name, seed string) string {
	suffix := "-" + shortDigest(seed)
	if len(name)+len(suffix) > MaxVaultNameLength {
		name = name[:MaxVaultNameLength-len(suffix)]
	}
	return strings.TrimRight(name, "-") + suffix
}

func truncateWithDigest(name, seed string) string {
	suffix := "-" + shortDigest(seed)
	return strings.TrimRight(name[:MaxVaultNameLength-len(suffix)], "-") + suffix
}

func shortDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])[:8]
}

// NormalizeHost lowercases a hostname and strips the root label's trailing dot,
// so that "Example.COM." and "example.com" compare equal.
func NormalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func isASCIILetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
