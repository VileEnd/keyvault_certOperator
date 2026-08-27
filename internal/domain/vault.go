package domain

import "strings"

// VaultAllowlist bounds which Key Vaults this operator may write to.
//
// Without it the vault is chosen entirely by whoever writes the custom
// resource: spec.keyVault.vaultURL accepts any https URL, so any user able to
// create a sync resource in a watched namespace can point the operator at any
// host. Azure RBAC still refuses the write -- the identity holds its role on
// one vault -- but the operator has by then opened a connection to a
// user-chosen endpoint, and the resulting 403 looks retryable, so it backs off
// forever against a misconfiguration that will never resolve itself.
//
// This mirrors the zone allowlist that already fences issuance. The reasoning
// there was that anyone able to create an Ingress could otherwise trigger
// certificate issuance; the same argument applies to the vault, and this closes
// it on the Kubernetes side rather than relying on Azure to say no.
//
// Entries are normalised base vault URLs. An empty allowlist permits every
// vault, which is the behaviour that existed before this type and stays the
// default so an upgrade changes nothing on its own.
type VaultAllowlist []string

// Permits reports whether the allowlist admits this vault URL.
func (a VaultAllowlist) Permits(vaultURL string) bool {
	if len(a) == 0 {
		return true
	}
	target := normaliseVaultURL(vaultURL)
	for _, allowed := range a {
		if normaliseVaultURL(allowed) == target {
			return true
		}
	}
	return false
}

// Enforced reports whether the allowlist actually bounds anything, so callers
// can say so in status rather than leaving operators guessing.
func (a VaultAllowlist) Enforced() bool { return len(a) > 0 }

// String renders the allowlist for an error message.
func (a VaultAllowlist) String() string { return strings.Join(a, ", ") }

// normaliseVaultURL makes comparison insensitive to case and a trailing slash.
// Vault hosts are DNS names, so case carries no meaning, and Key Vault serves
// the same vault with or without the trailing slash.
func normaliseVaultURL(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "/"))
}
