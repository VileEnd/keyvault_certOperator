package azure

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

// ClientFactory builds a Key Vault certificates client for one vault URL.
// It is an injection point: tests supply a client backed by the SDK's fake
// server transport, production supplies NewClientFactory.
type ClientFactory func(vaultURL string) (*azcertificates.Client, error)

// NewClientFactory returns a ClientFactory that authenticates with cred.
func NewClientFactory(cred azcore.TokenCredential, opts *azcertificates.ClientOptions) ClientFactory {
	return func(vaultURL string) (*azcertificates.Client, error) {
		return azcertificates.NewClient(vaultURL, cred, opts)
	}
}

// Repository implements app.VaultRepository against Azure Key Vault.
//
// Clients are cached per vault URL because each one carries its own
// authentication pipeline and challenge-policy state; rebuilding them per
// reconcile would re-run the Key Vault auth challenge every time.
type Repository struct {
	newClient ClientFactory

	mu      sync.Mutex
	clients map[string]*azcertificates.Client
}

// NewRepository wires a Repository around a client factory.
func NewRepository(factory ClientFactory) *Repository {
	return &Repository{newClient: factory, clients: map[string]*azcertificates.Client{}}
}

// Snapshot reports what the vault holds for this certificate.
//
// Exactly one GetCertificate is issued. That single call yields both the leaf
// thumbprint and our chain-digest tag, which together are enough to decide
// whether an import is needed -- so the steady-state cost of a reconcile is one
// cheap read and no write.
func (r *Repository) Snapshot(ctx context.Context, ref app.VaultRef) (domain.VaultSnapshot, error) {
	client, err := r.clientFor(ref.VaultURL)
	if err != nil {
		return domain.VaultSnapshot{}, err
	}

	// An empty version means "the current one".
	resp, err := client.GetCertificate(ctx, ref.CertificateName, "", nil)
	if err != nil {
		if isNotFound(err) {
			return domain.VaultSnapshot{Exists: false}, nil
		}
		if isAccessDenied(err) {
			return domain.VaultSnapshot{}, accessDenied(ref, "reading", "get", err)
		}
		return domain.VaultSnapshot{}, fmt.Errorf("getting certificate %q: %w", ref.CertificateName, err)
	}

	snapshot := domain.VaultSnapshot{
		Exists:     true,
		Thumbprint: resp.X509Thumbprint,
		Enabled:    true,
	}
	// The chain digest is read from a tag rather than from the stored chain.
	// Fetching the chain itself would mean reading the addressable secret, which
	// needs secrets/getSecret -- a permission this operator deliberately never
	// requests, since it would also expose the private key.
	if value, ok := resp.Tags[app.TagChainDigest]; ok && value != nil {
		snapshot.ChainDigest = *value
	}
	if attrs := resp.Attributes; attrs != nil {
		if attrs.Enabled != nil {
			snapshot.Enabled = *attrs.Enabled
		}
		if attrs.Expires != nil {
			snapshot.NotAfter = *attrs.Expires
		}
	}
	return snapshot, nil
}

// Import uploads a new version of the certificate.
//
// PreserveCertOrder is deliberately left unset. Its default of false makes Key
// Vault normalise the leaf to index 0, which is a free safety net for
// Application Gateway's requirement that the leaf be topmost.
func (r *Repository) Import(ctx context.Context, ref app.VaultRef, req app.ImportRequest) (app.ImportResult, error) {
	client, err := r.clientFor(ref.VaultURL)
	if err != nil {
		return app.ImportResult{}, err
	}

	encoded := base64.StdEncoding.EncodeToString(req.Blob)
	params := azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &encoded,
		CertificatePolicy: &azcertificates.CertificatePolicy{
			SecretProperties: &azcertificates.SecretProperties{ContentType: &req.ContentType},
		},
		Tags: toAzureTags(req.Tags),
	}
	// Key Vault discards the password on import and re-encodes the certificate,
	// so this value is never persisted anywhere.
	if req.Password != "" {
		params.Password = &req.Password
	}

	resp, err := client.ImportCertificate(ctx, ref.CertificateName, params, nil)
	if err != nil {
		if isAccessDenied(err) {
			return app.ImportResult{}, accessDenied(ref, "importing", "import", err)
		}
		return app.ImportResult{}, fmt.Errorf("importing certificate %q: %w", ref.CertificateName, err)
	}

	result := app.ImportResult{Thumbprint: resp.X509Thumbprint}
	if resp.ID != nil {
		result.Version = resp.ID.Version()
	}
	return result, nil
}

func (r *Repository) clientFor(vaultURL string) (*azcertificates.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if client, ok := r.clients[vaultURL]; ok {
		return client, nil
	}
	client, err := r.newClient(vaultURL)
	if err != nil {
		return nil, fmt.Errorf("creating Key Vault client for %q: %w", vaultURL, err)
	}
	r.clients[vaultURL] = client
	return client, nil
}

// isNotFound distinguishes "this certificate does not exist yet", which is a
// normal first-run state, from a real failure.
func isNotFound(err error) bool {
	var respErr *azcore.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound
}

// isAccessDenied reports whether the vault refused the call on authorization
// grounds rather than transiently.
//
// 401 counts alongside 403 because Key Vault answers a token it will not accept
// with 401, and the repair is the same permanent one. This looks at the vault's
// own response only: a credential that never produced a token fails earlier, in
// azidentity, and stays an ordinary retryable error -- one round of AAD
// unavailability should not be reported as a missing permission.
func isAccessDenied(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	return respErr.StatusCode == http.StatusForbidden || respErr.StatusCode == http.StatusUnauthorized
}

// accessDenied names the two grants a 401 or 403 can be missing, because the
// vault itself reports neither.
//
// The access-policy half is the one worth spelling out: on a vault with
// enableRbacAuthorization=false, a role assignment is accepted by ARM, shows up
// correctly in the portal, and grants precisely nothing -- which is why this
// failure is so often chased as a transient fault.
func accessDenied(ref app.VaultRef, action, permission string, err error) error {
	return fmt.Errorf("%w: %s %q in %s requires the certificates/%s permission; "+
		"grant it as a certificate access policy when the vault has "+
		"enableRbacAuthorization=false, where role assignments are ignored, and as a "+
		"Key Vault Certificates Officer role assignment when it is true: %w",
		domain.ErrVaultAccessDenied, action, ref.CertificateName, ref.VaultURL, permission, err)
}

func toAzureTags(tags map[string]string) map[string]*string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]*string, len(tags))
	for key, value := range tags {
		out[key] = &value
	}
	return out
}
