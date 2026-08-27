package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/testutil"
)

func TestDecide(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "intermediate R10")
	rotated := root.Intermediate(t, "intermediate R11")
	now := time.Now()

	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com", "x.com"}})
	bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	other := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com"}})
	otherBundle, err := domain.ParseBundle(other.CertPEM(t), other.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	// Same leaf, rotated intermediate: the CA changed its chain.
	reissued, err := domain.ParseBundle(
		append(leaf.LeafOnlyPEM(t), testutil.EncodeCertPEM(t, rotated.Cert)...),
		leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	current := domain.VaultSnapshot{
		Exists:      true,
		Thumbprint:  bundle.Thumbprint(),
		ChainDigest: bundle.ChainDigest(),
		Enabled:     true,
		NotAfter:    bundle.NotAfter(),
	}

	tests := []struct {
		name       string
		desired    *domain.Bundle
		snapshot   domain.VaultSnapshot
		wantAction domain.Action
		wantReason string
	}{
		{
			// The case that matters most. ImportCertificate is not idempotent:
			// every call mints a permanent version, so an unchanged certificate
			// must produce no API call at all.
			name:       "unchanged certificate is not re-imported",
			desired:    bundle,
			snapshot:   current,
			wantAction: domain.ActionNone,
			wantReason: domain.ReasonUpToDate,
		},
		{
			name:       "absent from the vault",
			desired:    bundle,
			snapshot:   domain.VaultSnapshot{Exists: false},
			wantAction: domain.ActionImport,
			wantReason: domain.ReasonAbsentInVault,
		},
		{
			name:       "renewed leaf",
			desired:    otherBundle,
			snapshot:   current,
			wantAction: domain.ActionImport,
			wantReason: domain.ReasonLeafChanged,
		},
		{
			// The leaf thumbprint cannot see an intermediate rotation, which is
			// why the chain digest is compared as well.
			name:       "rotated intermediate with an identical leaf",
			desired:    reissued,
			snapshot:   current,
			wantAction: domain.ActionImport,
			wantReason: domain.ReasonChainChanged,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := domain.Decide(tc.desired, tc.snapshot, now)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if got.Action != tc.wantAction {
				t.Errorf("action = %q, want %q", got.Action, tc.wantAction)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.wantReason)
			}
		})
	}
}

func TestDecideRejectsExpiredCertificates(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	now := time.Now()
	leaf := root.Issue(t, testutil.LeafOptions{
		DNSNames:  []string{"*.x.com"},
		NotBefore: now.Add(-48 * time.Hour),
		NotAfter:  now.Add(-time.Hour),
	})
	bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	// Key Vault refuses expired certificates with an opaque 400; catching it
	// here produces an actionable condition instead.
	if _, err := domain.Decide(bundle, domain.VaultSnapshot{}, now); !errors.Is(err, domain.ErrExpired) {
		t.Errorf("Decide() = %v, want ErrExpired", err)
	}
}

func TestDecideWarnsOnExpiryRegression(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	now := time.Now()

	leaf := root.Issue(t, testutil.LeafOptions{
		DNSNames: []string{"*.x.com"},
		NotAfter: now.Add(10 * 24 * time.Hour),
	})
	bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	// Key Vault holds something newer than the cluster does. The cluster stays
	// the source of truth, so we still import, but this is nearly always a
	// mistake and must be visible.
	got, err := domain.Decide(bundle, domain.VaultSnapshot{
		Exists:     true,
		Thumbprint: []byte("different"),
		NotAfter:   now.Add(60 * 24 * time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.Action != domain.ActionImport {
		t.Errorf("action = %q, want Import", got.Action)
	}
	if got.Warning == "" {
		t.Error("expected a warning about the expiry regression")
	}
}

func TestDecideReportsADisabledCertificate(t *testing.T) {
	t.Parallel()
	// The one state where "Key Vault holds this exact certificate" and "the
	// listener is serving it" come apart. Every thumbprint matches, so without
	// this the sync reports UpToDate while the site is down.
	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "intermediate R10")
	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com", "x.com"}})
	bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	snap := domain.VaultSnapshot{
		Exists:      true,
		Thumbprint:  bundle.Thumbprint(),
		ChainDigest: bundle.ChainDigest(),
		Enabled:     false,
		NotAfter:    bundle.NotAfter(),
	}

	decision, err := domain.Decide(bundle, snap, bundle.NotAfter().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	// Reported, not repaired: re-importing would mint a version per reconcile
	// and undo a deliberate act on a security-sensitive object.
	if decision.Action != domain.ActionNone {
		t.Errorf("action = %q, want %q", decision.Action, domain.ActionNone)
	}
	if decision.WarningReason != domain.ReasonDisabledInVault {
		t.Errorf("warningReason = %q, want %q", decision.WarningReason, domain.ReasonDisabledInVault)
	}
	if decision.Warning == "" {
		t.Error("a disabled certificate produced no warning at all")
	}

	// And an enabled one must stay quiet, or the warning means nothing.
	snap.Enabled = true
	enabled, err := domain.Decide(bundle, snap, bundle.NotAfter().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if enabled.Warning != "" {
		t.Errorf("an enabled certificate warned: %q", enabled.Warning)
	}
}
