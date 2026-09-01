package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/testutil"
)

// The ports are small enough that hand-written fakes beat generated mocks: they
// keep the test suite dependency-free and make call-count assertions explicit.

type fakeSource struct {
	bundle *domain.Bundle
	err    error
}

func (f *fakeSource) Load(context.Context, app.SecretRef) (*domain.Bundle, error) {
	return f.bundle, f.err
}

type fakeVault struct {
	snapshot     domain.VaultSnapshot
	snapshotErr  error
	importErr    error
	imports      []app.ImportRequest
	importedRefs []app.VaultRef
}

func (f *fakeVault) Snapshot(context.Context, app.VaultRef) (domain.VaultSnapshot, error) {
	return f.snapshot, f.snapshotErr
}

func (f *fakeVault) Import(_ context.Context, ref app.VaultRef, req app.ImportRequest) (app.ImportResult, error) {
	if f.importErr != nil {
		return app.ImportResult{}, f.importErr
	}
	f.imports = append(f.imports, req)
	f.importedRefs = append(f.importedRefs, ref)
	return app.ImportResult{Version: "v1"}, nil
}

type fakeEncoder struct {
	calls int
	err   error
}

func (f *fakeEncoder) Encode(*domain.Bundle) ([]byte, string, error) {
	f.calls++
	if f.err != nil {
		return nil, "", f.err
	}
	return []byte("pfx"), "changeit", nil
}

func (f *fakeEncoder) ContentType() string { return app.ContentTypePKCS12 }

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func newBundle(t *testing.T, dnsNames ...string) *domain.Bundle {
	t.Helper()
	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "test intermediate")
	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: dnsNames})
	bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	return bundle
}

func newSyncer(source *fakeSource, vault *fakeVault, encoder *fakeEncoder) *app.Syncer {
	syncer := app.NewSyncer(source, vault, encoder)
	syncer.Clock = fixedClock{now: time.Now()}
	return syncer
}

func request() app.SyncRequest {
	return app.SyncRequest{
		Source: app.SecretRef{Namespace: "certs", Name: "wildcard-x-com-tls"},
		Vault:  app.VaultRef{VaultURL: "https://my-vault.vault.azure.net", CertificateName: "wildcard-x-com"},
	}
}

func TestSyncDoesNotReimportAnUnchangedCertificate(t *testing.T) {
	t.Parallel()
	// The single most important behaviour in this operator. Key Vault's import
	// is not idempotent: every call mints a version that can never be deleted
	// and that Application Gateway may rotate to. A steady-state reconcile must
	// therefore perform no import and no encode at all.
	bundle := newBundle(t, "*.x.com", "x.com")
	vault := &fakeVault{snapshot: domain.VaultSnapshot{
		Exists:      true,
		Enabled:     true,
		Thumbprint:  bundle.Thumbprint(),
		ChainDigest: bundle.ChainDigest(),
		NotAfter:    bundle.NotAfter(),
	}}
	encoder := &fakeEncoder{}

	outcome, err := newSyncer(&fakeSource{bundle: bundle}, vault, encoder).Sync(t.Context(), request())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if outcome.Action != domain.ActionNone {
		t.Errorf("action = %q, want None", outcome.Action)
	}
	if len(vault.imports) != 0 {
		t.Errorf("performed %d imports, want 0", len(vault.imports))
	}
	if encoder.calls != 0 {
		t.Errorf("encoded %d times, want 0 -- the private key should not even be marshalled", encoder.calls)
	}
}

func TestSyncImportsWhenAbsent(t *testing.T) {
	t.Parallel()
	bundle := newBundle(t, "*.x.com", "x.com")
	vault := &fakeVault{snapshot: domain.VaultSnapshot{Exists: false}}

	outcome, err := newSyncer(&fakeSource{bundle: bundle}, vault, &fakeEncoder{}).Sync(t.Context(), request())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if outcome.Action != domain.ActionImport || outcome.Reason != domain.ReasonAbsentInVault {
		t.Errorf("got %q/%q, want Import/%s", outcome.Action, outcome.Reason, domain.ReasonAbsentInVault)
	}
	if len(vault.imports) != 1 {
		t.Fatalf("performed %d imports, want 1", len(vault.imports))
	}

	imported := vault.imports[0]
	// PKCS#12 rather than PEM: Microsoft's docs contradict each other on
	// Application Gateway's PEM support but agree on PFX.
	if imported.ContentType != app.ContentTypePKCS12 {
		t.Errorf("content type = %q, want %q", imported.ContentType, app.ContentTypePKCS12)
	}
	// The chain digest tag is what makes a CA intermediate rotation detectable,
	// since Key Vault's own thumbprint covers the leaf only.
	if imported.Tags[app.TagChainDigest] != bundle.ChainDigest() {
		t.Errorf("chain digest tag = %q, want %q", imported.Tags[app.TagChainDigest], bundle.ChainDigest())
	}
	if imported.Tags[app.TagManagedBy] != app.TagManagedByValue {
		t.Errorf("managed-by tag = %q, want %q", imported.Tags[app.TagManagedBy], app.TagManagedByValue)
	}
	if imported.Tags[app.TagSourceSecret] != "wildcard-x-com-tls" {
		t.Errorf("source-secret tag = %q", imported.Tags[app.TagSourceSecret])
	}
}

func TestSyncImportsOnChange(t *testing.T) {
	t.Parallel()
	bundle := newBundle(t, "*.x.com")

	tests := []struct {
		name       string
		snapshot   domain.VaultSnapshot
		wantReason string
	}{
		{
			name: "renewed leaf",
			snapshot: domain.VaultSnapshot{
				Exists: true, Enabled: true,
				Thumbprint:  []byte("stale"),
				ChainDigest: bundle.ChainDigest(),
			},
			wantReason: domain.ReasonLeafChanged,
		},
		{
			// Identical leaf, different chain: a CA intermediate rotation.
			name: "rotated intermediate",
			snapshot: domain.VaultSnapshot{
				Exists: true, Enabled: true,
				Thumbprint:  bundle.Thumbprint(),
				ChainDigest: "an-older-chain",
			},
			wantReason: domain.ReasonChainChanged,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			vault := &fakeVault{snapshot: tc.snapshot}
			outcome, err := newSyncer(&fakeSource{bundle: bundle}, vault, &fakeEncoder{}).Sync(t.Context(), request())
			if err != nil {
				t.Fatalf("Sync: %v", err)
			}
			if outcome.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", outcome.Reason, tc.wantReason)
			}
			if len(vault.imports) != 1 {
				t.Errorf("performed %d imports, want 1", len(vault.imports))
			}
		})
	}
}

func TestSyncReportsTheVersionlessSecretIdentifier(t *testing.T) {
	t.Parallel()
	// Application Gateway must be pointed at a versionless URI. A versioned one
	// pins the listener to a single version and silently disables the four-hourly
	// automatic rotation, which is the whole mechanism this operator relies on.
	bundle := newBundle(t, "*.x.com")
	vault := &fakeVault{snapshot: domain.VaultSnapshot{Exists: false}}

	outcome, err := newSyncer(&fakeSource{bundle: bundle}, vault, &fakeEncoder{}).Sync(t.Context(), request())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	const want = "https://my-vault.vault.azure.net/secrets/wildcard-x-com"
	if outcome.SecretIdentifier != want {
		t.Errorf("secret identifier = %q, want %q", outcome.SecretIdentifier, want)
	}
}

func TestSyncRefusesExpiredCertificatesBeforeCallingAzure(t *testing.T) {
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

	vault := &fakeVault{snapshot: domain.VaultSnapshot{Exists: false}}
	syncer := app.NewSyncer(&fakeSource{bundle: bundle}, vault, &fakeEncoder{})
	syncer.Clock = fixedClock{now: now}

	// Key Vault would reject this with an opaque 400; failing locally gives the
	// user something actionable and spends no API quota.
	if _, err := syncer.Sync(t.Context(), request()); !errors.Is(err, domain.ErrExpired) {
		t.Errorf("Sync() = %v, want ErrExpired", err)
	}
	if len(vault.imports) != 0 {
		t.Errorf("performed %d imports, want 0", len(vault.imports))
	}
}

func TestSyncValidatesTheVaultCertificateName(t *testing.T) {
	t.Parallel()
	bundle := newBundle(t, "*.x.com")
	vault := &fakeVault{}

	req := request()
	req.Vault.CertificateName = "wildcard.x.com" // dots are not legal in Key Vault names

	_, err := newSyncer(&fakeSource{bundle: bundle}, vault, &fakeEncoder{}).Sync(t.Context(), req)
	if !errors.Is(err, domain.ErrInvalidVaultName) {
		t.Errorf("Sync() = %v, want ErrInvalidVaultName", err)
	}
}

func TestSyncPropagatesVaultErrors(t *testing.T) {
	t.Parallel()
	bundle := newBundle(t, "*.x.com")
	sentinel := errors.New("key vault unavailable")

	_, err := newSyncer(
		&fakeSource{bundle: bundle},
		&fakeVault{snapshotErr: sentinel},
		&fakeEncoder{},
	).Sync(t.Context(), request())

	if !errors.Is(err, sentinel) {
		t.Errorf("Sync() = %v, want it to wrap %v", err, sentinel)
	}
}

func TestSyncBlamesTheEncoderRatherThanTheVault(t *testing.T) {
	t.Parallel()
	// Encoding happens in this process, before a single byte is sent, so a
	// failure here says nothing about Key Vault -- and reporting it as a vault
	// error is what sent people to the Azure portal for a local problem.
	bundle := newBundle(t, "*.x.com")
	vault := &fakeVault{snapshot: domain.VaultSnapshot{Exists: false}}
	sentinel := errors.New("pkcs12: unsupported private key type")

	_, err := newSyncer(&fakeSource{bundle: bundle}, vault, &fakeEncoder{err: sentinel}).
		Sync(t.Context(), request())

	if !errors.Is(err, domain.ErrPKCS12Encoding) {
		t.Errorf("Sync() = %v, want it to wrap ErrPKCS12Encoding", err)
	}
	// The cause still has to travel: the sentinel says which subsystem failed,
	// not what went wrong inside it.
	if !errors.Is(err, sentinel) {
		t.Errorf("Sync() = %v, want it to wrap %v", err, sentinel)
	}
	if len(vault.imports) != 0 {
		t.Errorf("imports = %d, want 0 -- nothing was encoded to send", len(vault.imports))
	}
}

func TestSyncDerivesTheVaultNameFromTheCertificateSANs(t *testing.T) {
	t.Parallel()
	// Leaving certificateName unset must produce a usable Key Vault name from
	// the certificate itself, so the common case needs no configuration.
	bundle := newBundle(t, "x.com", "*.x.com")
	vault := &fakeVault{snapshot: domain.VaultSnapshot{Exists: false}}

	req := request()
	req.Vault.CertificateName = ""

	outcome, err := newSyncer(&fakeSource{bundle: bundle}, vault, &fakeEncoder{}).Sync(t.Context(), req)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// The wildcard identifies the certificate better than the apex does.
	if outcome.CertificateName != "wildcard-x-com" {
		t.Errorf("certificate name = %q, want wildcard-x-com", outcome.CertificateName)
	}
	if outcome.SecretIdentifier != "https://my-vault.vault.azure.net/secrets/wildcard-x-com" {
		t.Errorf("secret identifier = %q", outcome.SecretIdentifier)
	}
}
