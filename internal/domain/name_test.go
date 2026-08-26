package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

func TestDeriveVaultCertificateName(t *testing.T) {
	t.Parallel()
	// Key Vault names allow only [0-9a-zA-Z-], so dots and the wildcard asterisk
	// both have to go.
	tests := []struct {
		name    string
		dnsName string
		want    string
		wantErr bool
	}{
		{"wildcard", "*.example.com", "wildcard-example-com", false},
		{"nested wildcard", "*.sub.example.com", "wildcard-sub-example-com", false},
		{"apex", "example.com", "example-com", false},
		{"host", "api.example.com", "api-example-com", false},
		{"uppercase is normalised", "*.EXAMPLE.COM", "wildcard-example-com", false},
		{"trailing root dot is stripped", "*.example.com.", "wildcard-example-com", false},
		{"leading digit gains a prefix", "1api.example.com", "cert-1api-example-com", false},
		{"empty", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := domain.DeriveVaultCertificateName(tc.dnsName)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DeriveVaultCertificateName: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if err := domain.ValidateVaultCertificateName(got); err != nil {
				t.Errorf("derived name is not valid for Key Vault: %v", err)
			}
		})
	}
}

func TestDeriveVaultCertificateNameStaysWithinAzureLimit(t *testing.T) {
	t.Parallel()
	long := "*." + strings.Repeat("verylonglabel.", 20) + "example.com"

	got, err := domain.DeriveVaultCertificateName(long)
	if err != nil {
		t.Fatalf("DeriveVaultCertificateName: %v", err)
	}
	if len(got) > domain.MaxVaultNameLength {
		t.Errorf("name length = %d, exceeds Azure's limit of %d", len(got), domain.MaxVaultNameLength)
	}
	if err := domain.ValidateVaultCertificateName(got); err != nil {
		t.Errorf("truncated name is invalid: %v", err)
	}
}

func TestValidateVaultCertificateName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"simple", "wildcard-example-com", true},
		{"digits after the first character", "a1b2", true},
		{"empty", "", false},
		{"contains a dot", "wildcard.example.com", false},
		{"contains an asterisk", "*-example-com", false},
		{"contains an underscore", "wildcard_example", false},
		{"leading digit", "1example", false},
		{"too long", strings.Repeat("a", domain.MaxVaultNameLength+1), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := domain.ValidateVaultCertificateName(tc.input)
			if tc.valid && err != nil {
				t.Errorf("expected %q to be valid, got %v", tc.input, err)
			}
			if !tc.valid && !errors.Is(err, domain.ErrInvalidVaultName) {
				t.Errorf("expected ErrInvalidVaultName for %q, got %v", tc.input, err)
			}
		})
	}
}

func TestDisambiguateVaultName(t *testing.T) {
	t.Parallel()
	// The dot-to-hyphen mapping is not injective: these two distinct hostnames
	// derive the same Key Vault name, so callers must be able to separate them.
	a, err := domain.DeriveVaultCertificateName("foo.example.com")
	if err != nil {
		t.Fatalf("DeriveVaultCertificateName: %v", err)
	}
	b, err := domain.DeriveVaultCertificateName("foo-example.com")
	if err != nil {
		t.Fatalf("DeriveVaultCertificateName: %v", err)
	}
	if a != b {
		t.Fatalf("precondition failed: expected a collision, got %q and %q", a, b)
	}

	got := domain.DisambiguateVaultName(b, "foo-example.com")
	if got == a {
		t.Error("DisambiguateVaultName did not break the collision")
	}
	if err := domain.ValidateVaultCertificateName(got); err != nil {
		t.Errorf("disambiguated name is invalid: %v", err)
	}
}
