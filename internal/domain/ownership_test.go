package domain_test

import (
	"errors"
	"testing"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

func TestCheckOwnership(t *testing.T) {
	t.Parallel()
	const mine = "certs/wildcard-x-com-tls"

	absent := domain.VaultSnapshot{}
	ownedByMe := domain.VaultSnapshot{Exists: true, ManagedSource: mine}
	ownedByOther := domain.VaultSnapshot{Exists: true, ManagedSource: "team-b/their-tls"}
	untagged := domain.VaultSnapshot{Exists: true}

	tests := []struct {
		name    string
		snap    domain.VaultSnapshot
		mode    domain.OwnershipMode
		refused bool
	}{
		{"absent", absent, domain.OwnershipStrict, false},
		{"own certificate", ownedByMe, domain.OwnershipStrict, false},
		// The case the check exists for: a sync naming a certificate that a
		// listener is already serving from someone else's Secret.
		{"another sync's certificate", ownedByOther, domain.OwnershipAdoptUntagged, true},
		{"another sync's certificate, zero value mode", ownedByOther, "", true},
		// Uploaded by hand, or replaced out of band: adopting it is how the
		// operator took over existing certificates before, and still does.
		{"untagged, default", untagged, domain.OwnershipAdoptUntagged, false},
		{"untagged, strict", untagged, domain.OwnershipStrict, true},
		{"off checks nothing", ownedByOther, domain.OwnershipOff, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := domain.CheckOwnership(tc.snap, mine, tc.mode)
			if tc.refused != errors.Is(err, domain.ErrVaultCertificateNotOwned) {
				t.Errorf("CheckOwnership = %v, want refused=%v", err, tc.refused)
			}
		})
	}
}

func TestParseOwnershipModeRejectsUnknownValues(t *testing.T) {
	t.Parallel()
	// A typo must fail at startup, not silently fall back to checking nothing.
	if _, err := domain.ParseOwnershipMode("strcit"); err == nil {
		t.Error("ParseOwnershipMode accepted an unknown mode")
	}
	if mode, err := domain.ParseOwnershipMode(""); err != nil || mode != domain.OwnershipAdoptUntagged {
		t.Errorf("ParseOwnershipMode(\"\") = %q, %v; want the default", mode, err)
	}
}
