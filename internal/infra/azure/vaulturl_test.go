package azure_test

import (
	"testing"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/azure"
)

func TestVaultURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		cloud   azure.Cloud
		want    string
		wantErr bool
	}{
		{"bare name defaults to public cloud", "my-vault", "", "https://my-vault.vault.azure.net", false},
		{"explicit public cloud", "my-vault", azure.CloudPublic, "https://my-vault.vault.azure.net", false},
		{"us government", "my-vault", azure.CloudUSGovernment, "https://my-vault.vault.usgovcloudapi.net", false},
		{"china", "my-vault", azure.CloudChina, "https://my-vault.vault.azure.cn", false},
		{"explicit URL passes through", "https://my-vault.vault.azure.net", "", "https://my-vault.vault.azure.net", false},
		{"trailing slash is trimmed", "https://my-vault.vault.azure.net/", "", "https://my-vault.vault.azure.net", false},
		{"private endpoint URL", "https://my-vault.privatelink.vaultcore.azure.net", "", "https://my-vault.privatelink.vaultcore.azure.net", false},
		{"empty", "", "", "", true},
		{"plaintext URL", "http://my-vault.vault.azure.net", "", "", true},
		{"name too short", "ab", "", "", true},
		{"illegal character", "my_vault", "", "", true},
		{"trailing hyphen", "my-vault-", "", "", true},
		{"unknown cloud", "my-vault", "AzureMoonCloud", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := azure.VaultURL(tc.input, tc.cloud)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("VaultURL: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVaultURLProducesAUsableSecretIdentifier(t *testing.T) {
	t.Parallel()
	// The trailing slash matters: Application Gateway compares the configured
	// keyVaultSecretId as a string, and a doubled slash would not match.
	vaultURL, err := azure.VaultURL("https://my-vault.vault.azure.net/", azure.CloudPublic)
	if err != nil {
		t.Fatalf("VaultURL: %v", err)
	}
	ref := app.VaultRef{VaultURL: vaultURL, CertificateName: "wildcard-x-com"}

	const want = "https://my-vault.vault.azure.net/secrets/wildcard-x-com"
	if got := ref.SecretIdentifier(); got != want {
		t.Errorf("secret identifier = %q, want %q", got, want)
	}
}

// The field's only schema constraint is ^https://.+$, so without a host check
// anyone able to write the resource could aim the operator's Key Vault client
// at a host of their choosing.
func TestVaultURLRejectsHostsThatAreNotKeyVaults(t *testing.T) {
	t.Parallel()
	for _, target := range []string{
		"https://attacker.example.com",
		"https://10.0.0.5:8443/anything",
		"https://vault.azure.net",            // the bare suffix is not a vault
		"https://notvault.azure.net.evil.io", // suffix must be a real label boundary
	} {
		if got, err := azure.VaultURL(target, azure.CloudPublic); err == nil {
			t.Errorf("VaultURL(%q) = %q, want an error", target, got)
		}
	}
}

func TestVaultURLAcceptsEveryCloudsVaultHost(t *testing.T) {
	t.Parallel()
	// Accepted regardless of the cloud argument: cloud describes how a bare
	// name is resolved and is not necessarily set alongside an explicit URL.
	for _, target := range []string{
		"https://v.vault.azure.net",
		"https://v.vault.usgovcloudapi.net",
		"https://v.vault.azure.cn",
		// Private endpoints are addressed through the privatelink zone, which
		// is a different host from the public one -- not merely a different IP.
		"https://v.privatelink.vaultcore.azure.net",
		"https://v.privatelink.vaultcore.usgovcloudapi.net",
		"https://v.privatelink.vaultcore.azure.cn",
	} {
		if _, err := azure.VaultURL(target, azure.CloudPublic); err != nil {
			t.Errorf("VaultURL(%q) returned %v, want it accepted", target, err)
		}
	}
}

func TestVaultNameRulesMatchAzure(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"9abc", // must begin with a letter
		"a--b", // no consecutive hyphens
		"ab",   // too short
		"-abc", // must begin with a letter
		"abc-", // must end with a letter or digit
	} {
		if got, err := azure.VaultURL(name, azure.CloudPublic); err == nil {
			t.Errorf("VaultURL(%q) = %q, want an error", name, got)
		}
	}
	for _, name := range []string{"abc", "a-b-c", "my-vault9"} {
		if _, err := azure.VaultURL(name, azure.CloudPublic); err != nil {
			t.Errorf("VaultURL(%q) returned %v, want it accepted", name, err)
		}
	}
}
