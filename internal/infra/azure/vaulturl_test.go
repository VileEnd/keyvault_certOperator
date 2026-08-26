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
