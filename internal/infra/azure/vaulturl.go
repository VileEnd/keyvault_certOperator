// Package azure adapts Azure Key Vault to the ports declared in internal/app.
package azure

import (
	"fmt"
	"net/url"
	"strings"
)

// Cloud names the Azure environment a vault lives in.
type Cloud string

const (
	// CloudPublic is global Azure.
	CloudPublic Cloud = "AzurePublicCloud"
	// CloudUSGovernment is Azure Government.
	CloudUSGovernment Cloud = "AzureUSGovernmentCloud"
	// CloudChina is Azure operated by 21Vianet.
	CloudChina Cloud = "AzureChinaCloud"
)

var vaultSuffixes = map[Cloud]string{
	CloudPublic:       "vault.azure.net",
	CloudUSGovernment: "vault.usgovcloudapi.net",
	CloudChina:        "vault.azure.cn",
}

// VaultURL resolves a vault name or an explicit URL into a base vault URL.
//
// Accepting a bare name keeps the common case terse while an explicit URL still
// covers sovereign clouds and private endpoints. The result never has a trailing
// slash, so callers can append paths without producing a double slash -- which
// matters because the versionless secret identifier is compared as a string by
// Application Gateway.
func VaultURL(nameOrURL string, cloud Cloud) (string, error) {
	value := strings.TrimSpace(nameOrURL)
	if value == "" {
		return "", fmt.Errorf("key vault name or URL is required")
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return "", fmt.Errorf("parsing key vault URL %q: %w", value, err)
		}
		if parsed.Scheme != "https" || parsed.Host == "" {
			return "", fmt.Errorf("key vault URL %q must be an https URL with a host", value)
		}
		return strings.TrimSuffix(parsed.Scheme+"://"+parsed.Host+parsed.Path, "/"), nil
	}

	if cloud == "" {
		cloud = CloudPublic
	}
	suffix, ok := vaultSuffixes[cloud]
	if !ok {
		return "", fmt.Errorf("unknown Azure cloud %q", cloud)
	}
	if err := validateVaultName(value); err != nil {
		return "", err
	}
	return "https://" + value + "." + suffix, nil
}

// validateVaultName applies Azure's vault naming rules: 3-24 characters of
// letters, digits and hyphens, starting with a letter and not ending with one.
func validateVaultName(name string) error {
	if len(name) < 3 || len(name) > 24 {
		return fmt.Errorf("key vault name %q must be 3-24 characters", name)
	}
	for _, r := range name {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isDigit := r >= '0' && r <= '9'
		if !isLetter && !isDigit && r != '-' {
			return fmt.Errorf("key vault name %q may only contain letters, digits and hyphens", name)
		}
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return fmt.Errorf("key vault name %q must not start or end with a hyphen", name)
	}
	return nil
}
