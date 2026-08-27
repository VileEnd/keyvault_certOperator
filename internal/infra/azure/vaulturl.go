// Package azure adapts Azure Key Vault to the ports declared in internal/app.
package azure

import (
	"fmt"
	"net/url"
	"sort"
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

// vaultHostSuffixes is what an explicit URL's host is checked against. It is
// wider than vaultSuffixes, which only has to build a URL from a bare name.
//
// The vaultcore entries are not redundant. Microsoft lists both vault.<cloud>
// and vaultcore.<cloud> as Key Vault's public DNS forwarders, and a private
// endpoint is addressed through privatelink.vaultcore.<cloud> -- which ends in
// ".vaultcore.<cloud>" and is therefore covered by these without needing its
// own entry.
var vaultHostSuffixes = []string{
	"vault.azure.net", "vaultcore.azure.net",
	"vault.usgovcloudapi.net", "vaultcore.usgovcloudapi.net",
	"vault.azure.cn", "vaultcore.azure.cn",
}

// ParseCloud validates a cloud name, treating empty as the public cloud.
//
// Resolving a bare vault name against the wrong cloud produces a URL that is
// syntactically fine and can never work, so the name is checked once at startup
// rather than turning into a DNS failure the sync controller classifies as
// retryable and backs off against forever.
func ParseCloud(value string) (Cloud, error) {
	if strings.TrimSpace(value) == "" {
		return CloudPublic, nil
	}
	cloud := Cloud(strings.TrimSpace(value))
	if _, ok := vaultSuffixes[cloud]; !ok {
		return "", fmt.Errorf("unknown Azure cloud %q; expected one of %s",
			value, strings.Join(KnownClouds(), ", "))
	}
	return cloud, nil
}

// KnownClouds lists the accepted cloud names, sorted so messages are stable.
func KnownClouds() []string {
	out := make([]string, 0, len(vaultSuffixes))
	for cloud := range vaultSuffixes {
		out = append(out, string(cloud))
	}
	sort.Strings(out)
	return out
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
		// The host has to actually be a Key Vault. Without this the field
		// accepts any https URL, so anyone able to write the resource could
		// aim the operator's Key Vault client at a host of their choosing.
		// Azure would still refuse to mint a token for it, but the connection
		// is made before that, and the failure then looks retryable.
		//
		// Every cloud's suffix is accepted rather than only the one named in
		// spec.cloud, because cloud describes how a bare *name* is resolved
		// and is not necessarily set alongside an explicit URL. A private
		// endpoint does not change the suffix -- it changes what the name
		// resolves to -- so this stays compatible with one.
		if !isVaultHost(parsed.Hostname()) {
			return "", fmt.Errorf(
				"key vault URL %q does not name a Key Vault host; expected one ending in %s",
				value, strings.Join(knownVaultSuffixes(), ", "))
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

// isVaultHost reports whether a hostname belongs to a Key Vault in any Azure
// cloud. The comparison is on the DNS name only: url.Hostname() has already
// stripped any port, and a port is not part of a vault's identity.
func isVaultHost(hostname string) bool {
	host := strings.ToLower(hostname)
	for _, suffix := range vaultHostSuffixes {
		// The dot matters: "notvault.azure.net" must not pass as
		// "vault.azure.net", and a bare suffix is not itself a vault.
		if strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// knownVaultSuffixes lists the accepted suffixes, sorted so the error message
// is stable rather than dependent on map iteration order.
func knownVaultSuffixes() []string {
	suffixes := append([]string(nil), vaultHostSuffixes...)
	sort.Strings(suffixes)
	return suffixes
}

// validateVaultName applies Azure's vault naming rules: 3-24 characters of
// letters, digits and hyphens, beginning with a letter, ending with a letter or
// digit, and with no consecutive hyphens.
//
// These are checked here so a typo fails locally with a clear message rather
// than as a DNS error against a host that does not exist -- which the sync
// controller would classify as retryable and back off against forever.
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
	if !isASCIILetter(rune(name[0])) {
		return fmt.Errorf("key vault name %q must begin with a letter", name)
	}
	if name[len(name)-1] == '-' {
		return fmt.Errorf("key vault name %q must end with a letter or digit", name)
	}
	if strings.Contains(name, "--") {
		return fmt.Errorf("key vault name %q must not contain consecutive hyphens", name)
	}
	return nil
}

func isASCIILetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
