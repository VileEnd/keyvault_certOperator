package azure_test

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates/fake"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/azure"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/pkcs12"
	"github.com/VileEnd/keyvault_certOperator/internal/testutil"
)

const testVaultURL = "https://my-vault.vault.azure.net"

func testRef() app.VaultRef {
	return app.VaultRef{VaultURL: testVaultURL, CertificateName: "wildcard-x-com"}
}

// newRepository wires the real repository against the SDK's own fake server
// transport, so the adapter is exercised through the genuine client pipeline --
// serialisation, the challenge policy and error shapes included -- with no
// Azure account involved.
func newRepository(t *testing.T, server *fake.Server) *azure.Repository {
	t.Helper()
	return azure.NewRepository(func(vaultURL string) (*azcertificates.Client, error) {
		return azcertificates.NewClient(vaultURL, &azfake.TokenCredential{}, &azcertificates.ClientOptions{
			ClientOptions: azcore.ClientOptions{Transport: fake.NewServerTransport(server)},
		})
	})
}

func TestSnapshotTreatsAMissingCertificateAsAbsent(t *testing.T) {
	t.Parallel()
	// First run against an empty vault is a normal state, not a failure.
	server := &fake.Server{
		GetCertificate: func(_ testContext, _, _ string, _ *azcertificates.GetCertificateOptions) (
			resp azfake.Responder[azcertificates.GetCertificateResponse], errResp azfake.ErrorResponder) {
			errResp.SetResponseError(http.StatusNotFound, "CertificateNotFound")
			return
		},
	}

	snapshot, err := newRepository(t, server).Snapshot(t.Context(), testRef())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Exists {
		t.Error("expected Exists to be false for a missing certificate")
	}
}

func TestSnapshotReadsThumbprintAndChainDigest(t *testing.T) {
	t.Parallel()
	expires := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)
	digest := "abc123"
	enabled := true

	server := &fake.Server{
		GetCertificate: func(_ testContext, _, _ string, _ *azcertificates.GetCertificateOptions) (
			resp azfake.Responder[azcertificates.GetCertificateResponse], errResp azfake.ErrorResponder) {
			resp.SetResponse(http.StatusOK, azcertificates.GetCertificateResponse{
				Certificate: azcertificates.Certificate{
					X509Thumbprint: []byte{0x01, 0x02, 0x03},
					Tags:           map[string]*string{app.TagChainDigest: &digest},
					Attributes:     &azcertificates.CertificateAttributes{Enabled: &enabled, Expires: &expires},
				},
			}, nil)
			return
		},
	}

	snapshot, err := newRepository(t, server).Snapshot(t.Context(), testRef())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !snapshot.Exists {
		t.Fatal("expected Exists to be true")
	}
	if string(snapshot.Thumbprint) != string([]byte{0x01, 0x02, 0x03}) {
		t.Errorf("thumbprint = %x", snapshot.Thumbprint)
	}
	// The chain digest comes from a tag, which is what lets one GetCertificate
	// detect a CA intermediate rotation without ever reading the private key.
	if snapshot.ChainDigest != digest {
		t.Errorf("chain digest = %q, want %q", snapshot.ChainDigest, digest)
	}
	if !snapshot.NotAfter.Equal(expires) {
		t.Errorf("not after = %s, want %s", snapshot.NotAfter, expires)
	}
}

func TestImportSendsBase64PayloadContentTypeAndTags(t *testing.T) {
	t.Parallel()
	var got azcertificates.ImportCertificateParameters
	id := azcertificates.ID(testVaultURL + "/certificates/wildcard-x-com/abc123")

	server := &fake.Server{
		ImportCertificate: func(_ testContext, _ string, params azcertificates.ImportCertificateParameters,
			_ *azcertificates.ImportCertificateOptions) (
			resp azfake.Responder[azcertificates.ImportCertificateResponse], errResp azfake.ErrorResponder) {
			got = params
			resp.SetResponse(http.StatusOK, azcertificates.ImportCertificateResponse{
				Certificate: azcertificates.Certificate{ID: &id},
			}, nil)
			return
		},
	}

	result, err := newRepository(t, server).Import(t.Context(), testRef(), app.ImportRequest{
		Blob:        []byte("pretend-pfx"),
		Password:    "changeit",
		ContentType: app.ContentTypePKCS12,
		Tags:        map[string]string{app.TagChainDigest: "digest", app.TagManagedBy: app.TagManagedByValue},
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	if result.Version != "abc123" {
		t.Errorf("version = %q, want abc123", result.Version)
	}
	if got.Base64EncodedCertificate == nil ||
		*got.Base64EncodedCertificate != base64.StdEncoding.EncodeToString([]byte("pretend-pfx")) {
		t.Error("payload was not base64-encoded as Key Vault requires")
	}
	// Application Gateway rejects a Key Vault secret whose content type is not
	// application/x-pkcs12 or application/x-pem-file.
	if got.CertificatePolicy == nil || got.CertificatePolicy.SecretProperties == nil ||
		got.CertificatePolicy.SecretProperties.ContentType == nil ||
		*got.CertificatePolicy.SecretProperties.ContentType != app.ContentTypePKCS12 {
		t.Error("content type was not set to application/x-pkcs12 in the certificate policy")
	}
	// Left unset so Key Vault's default puts the leaf at index 0, which is what
	// Application Gateway requires.
	if got.PreserveCertOrder != nil {
		t.Error("PreserveCertOrder should be left unset")
	}
	if got.Tags[app.TagChainDigest] == nil || *got.Tags[app.TagChainDigest] != "digest" {
		t.Error("chain digest tag was not sent")
	}
}

func TestSyncAgainstTheVaultImportsOnceThenStops(t *testing.T) {
	t.Parallel()
	// The end-to-end guarantee, exercised through the real client pipeline:
	// the first pass imports, and a second pass over unchanged input performs no
	// import at all. Every import mints a permanent Key Vault version and is a
	// candidate Application Gateway rotation, so a loop that re-imported would
	// steadily degrade the vault.
	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "test intermediate")
	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com", "x.com"}})
	bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	var stored *azcertificates.Certificate
	imports := 0
	id := azcertificates.ID(testVaultURL + "/certificates/wildcard-x-com/v1")

	server := &fake.Server{
		GetCertificate: func(_ testContext, _, _ string, _ *azcertificates.GetCertificateOptions) (
			resp azfake.Responder[azcertificates.GetCertificateResponse], errResp azfake.ErrorResponder) {
			if stored == nil {
				errResp.SetResponseError(http.StatusNotFound, "CertificateNotFound")
				return
			}
			resp.SetResponse(http.StatusOK, azcertificates.GetCertificateResponse{Certificate: *stored}, nil)
			return
		},
		ImportCertificate: func(_ testContext, _ string, params azcertificates.ImportCertificateParameters,
			_ *azcertificates.ImportCertificateOptions) (
			resp azfake.Responder[azcertificates.ImportCertificateResponse], errResp azfake.ErrorResponder) {
			imports++
			// Model Key Vault's behaviour: the imported leaf's thumbprint and our
			// tags become the stored state.
			stored = &azcertificates.Certificate{
				ID:             &id,
				X509Thumbprint: bundle.Thumbprint(),
				Tags:           params.Tags,
			}
			resp.SetResponse(http.StatusOK, azcertificates.ImportCertificateResponse{Certificate: *stored}, nil)
			return
		},
	}

	encoder, err := pkcs12.NewEncoder(pkcs12.ProfileLegacy)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	syncer := app.NewSyncer(staticSource{bundle}, newRepository(t, server), encoder)
	req := app.SyncRequest{
		Source: app.SecretRef{Namespace: "certs", Name: "wildcard-x-com-tls"},
		Vault:  testRef(),
	}

	first, err := syncer.Sync(t.Context(), req)
	if err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	if first.Action != domain.ActionImport {
		t.Errorf("first pass action = %q, want Import", first.Action)
	}

	second, err := syncer.Sync(t.Context(), req)
	if err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	if second.Action != domain.ActionNone {
		t.Errorf("second pass action = %q, want None", second.Action)
	}
	if imports != 1 {
		t.Errorf("ImportCertificate called %d times, want exactly 1", imports)
	}
}
