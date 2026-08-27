package domain_test

import (
	"testing"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

func TestVaultAllowlistPermits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		allowed domain.VaultAllowlist
		vault   string
		want    bool
	}{
		// The default has to stay permissive, or upgrading the operator would
		// stop every existing resource working.
		{"empty permits anything", nil, "https://any.vault.azure.net", true},
		{"exact match", domain.VaultAllowlist{"https://a.vault.azure.net"}, "https://a.vault.azure.net", true},
		{"other vault refused", domain.VaultAllowlist{"https://a.vault.azure.net"}, "https://b.vault.azure.net", false},
		// Vault hosts are DNS names, so case carries no meaning.
		{"case insensitive", domain.VaultAllowlist{"https://A.Vault.Azure.Net"}, "https://a.vault.azure.net", true},
		// Key Vault serves the same vault either way.
		{"trailing slash", domain.VaultAllowlist{"https://a.vault.azure.net/"}, "https://a.vault.azure.net", true},
		{"one of several", domain.VaultAllowlist{"https://a.vault.azure.net", "https://b.vault.azure.net"}, "https://b.vault.azure.net", true},
		// A prefix must not pass: "a.vault.azure.net" is not "aa.vault.azure.net".
		{"prefix is not a match", domain.VaultAllowlist{"https://a.vault.azure.net"}, "https://aa.vault.azure.net", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.allowed.Permits(tc.vault); got != tc.want {
				t.Errorf("Permits(%q) = %v, want %v", tc.vault, got, tc.want)
			}
		})
	}
}

func TestVaultAllowlistEnforced(t *testing.T) {
	t.Parallel()
	if (domain.VaultAllowlist{}).Enforced() {
		t.Error("an empty allowlist must not report itself as enforced")
	}
	if !(domain.VaultAllowlist{"https://a.vault.azure.net"}).Enforced() {
		t.Error("a populated allowlist must report itself as enforced")
	}
}
