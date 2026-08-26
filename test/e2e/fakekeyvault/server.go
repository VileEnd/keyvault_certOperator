// Package fakekeyvault implements enough of the Azure Key Vault certificates
// REST API to exercise the real Azure SDK client over real HTTPS.
//
// It is not a mock of our own adapter: the operator talks to it through the
// genuine azcertificates client and pipeline, so serialization, base64
// encoding, the certificate policy shape, tags and the content type are all
// exercised for real. The fake also parses every uploaded archive as PKCS#12,
// which means an upload that Key Vault itself would reject fails the test here.
package fakekeyvault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- Key Vault's x5t is a SHA-1 identifier.
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Import records one certificate upload as the server received it.
type Import struct {
	Name        string
	ContentType string
	Tags        map[string]string
	Leaf        *x509.Certificate
	Chain       []*x509.Certificate
	Thumbprint  []byte
	Version     string
}

type stored struct {
	thumbprint []byte
	tags       map[string]string
	version    string
	notAfter   time.Time
}

// Server is a fake Key Vault listening over TLS.
type Server struct {
	http        *httptest.Server
	requireAuth bool
	caPEM       []byte
	leafDER     []byte
	tokenGrants int

	mu      sync.Mutex
	certs   map[string]stored
	imports []Import
	counter int
}

// VaultHost is the hostname the fake vault answers on.
//
// It has to be a genuine *.vault.azure.net name served on port 443, because the
// Key Vault SDK verifies that the challenge resource's host is a suffix of the
// vault host -- and the host it compares includes the port for any non-default
// one. Mapping this name to loopback therefore exercises the real challenge
// verification instead of switching it off.
const VaultHost = "e2e-fake.vault.azure.net"

// AuthorityHost is the login endpoint the fake also answers on, so token
// acquisition is exercised rather than bypassed.
const AuthorityHost = "login.microsoftonline.com"

// TenantID is the tenant the challenge points the credential at.
const TenantID = "11111111-1111-1111-1111-111111111111"

// New starts a fake Key Vault on an ephemeral port. Suitable for unit-style use
// where the challenge flow is not exercised.
func New() *Server {
	s := &Server{certs: map[string]stored{}}
	s.http = httptest.NewTLSServer(http.HandlerFunc(s.route))
	return s
}

// NewOnPort443 starts the fake bound to 127.0.0.1:443 with a certificate valid
// for both the vault and the login host, so the full challenge-and-token flow
// works end to end. The caller must map both names to loopback.
func NewOnPort443() (*Server, error) {
	s := &Server{certs: map[string]stored{}, requireAuth: true}

	cert, err := selfSigned(VaultHost, AuthorityHost)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		return nil, fmt.Errorf("binding 127.0.0.1:443: %w", err)
	}

	s.http = &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: http.HandlerFunc(s.route), ReadHeaderTimeout: 10 * time.Second},
		TLS:      &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	s.http.StartTLS()
	s.leafDER = cert.Certificate[0]
	s.caPEM = pemEncode(s.leafDER)
	return s, nil
}

// URL is the vault base URL to configure on a resource.
func (s *Server) URL() string {
	if s.requireAuth {
		return "https://" + VaultHost
	}
	return s.http.URL
}

// CACertPEM returns the PEM the client must trust to reach this server.
func (s *Server) CACertPEM() []byte {
	if len(s.caPEM) > 0 {
		return s.caPEM
	}
	return pemEncode(s.http.Certificate().Raw)
}

// TokenGrants reports how many access tokens the fake issued. A non-zero value
// proves the credential really authenticated rather than the request slipping
// through unauthenticated.
func (s *Server) TokenGrants() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenGrants
}

// Close shuts the server down.
func (s *Server) Close() { s.http.Close() }

// Imports returns every upload received so far.
func (s *Server) Imports() []Import {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Import(nil), s.imports...)
}

// ImportCount reports how many uploads a certificate name has received. This is
// the number the idempotency assertions turn on.
func (s *Server) ImportCount(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, imported := range s.imports {
		if imported.Name == name {
			n++
		}
	}
	return n
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	if s.serveEntra(w, r) {
		return
	}

	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] != "certificates" {
		http.Error(w, "unexpected path", http.StatusNotFound)
		return
	}
	name := parts[1]

	// Key Vault answers an unauthenticated request with a challenge rather than
	// a result. The SDK relies on this: it deliberately strips the request body
	// for the probe so certificate material is never sent to an endpoint it has
	// not yet authenticated against.
	if s.requireAuth && r.Header.Get("Authorization") == "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(
			`Bearer authorization="https://%s/%s", resource="https://vault.azure.net"`,
			AuthorityHost, TenantID))
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": map[string]any{"code": "Unauthorized", "message": "authentication required"},
		})
		return
	}

	switch {
	case r.Method == http.MethodPost && len(parts) == 3 && parts[2] == "import":
		s.importCertificate(w, r, name)
	case r.Method == http.MethodGet:
		s.getCertificate(w, name)
	default:
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getCertificate(w http.ResponseWriter, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.certs[name]
	if !ok {
		// Key Vault's shape for a missing object, which the adapter must read as
		// "absent" rather than as a failure.
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": map[string]any{"code": "CertificateNotFound", "message": "certificate not found"},
		})
		return
	}
	writeJSON(w, http.StatusOK, s.body(name, current))
}

func (s *Server) importCertificate(w http.ResponseWriter, r *http.Request, name string) {
	var params struct {
		Value  string            `json:"value"`
		Pwd    string            `json:"pwd"`
		Tags   map[string]string `json:"tags"`
		Policy struct {
			SecretProps struct {
				ContentType string `json:"contentType"`
			} `json:"secret_props"`
		} `json:"policy"`
		PreserveCertOrder *bool `json:"preserveCertOrder"`
	}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	blob, err := base64.StdEncoding.DecodeString(params.Value)
	if err != nil {
		http.Error(w, "value is not base64: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Parsing here is the point: if the operator ever produced an archive Key
	// Vault could not read, this rejects it exactly as Key Vault would.
	key, leaf, chain, err := gopkcs12.DecodeChain(blob, params.Pwd)
	if err != nil {
		http.Error(w, "pkcs#12 archive is unreadable: "+err.Error(), http.StatusBadRequest)
		return
	}
	if key == nil {
		http.Error(w, "archive has no private key", http.StatusBadRequest)
		return
	}

	sum := sha1.Sum(leaf.Raw) // #nosec G401 -- identifier, not a security primitive.

	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	version := fmt.Sprintf("%032x", s.counter)

	s.certs[name] = stored{
		thumbprint: sum[:],
		tags:       params.Tags,
		version:    version,
		notAfter:   leaf.NotAfter,
	}
	s.imports = append(s.imports, Import{
		Name:        name,
		ContentType: params.Policy.SecretProps.ContentType,
		Tags:        params.Tags,
		Leaf:        leaf,
		Chain:       chain,
		Thumbprint:  sum[:],
		Version:     version,
	})

	writeJSON(w, http.StatusOK, s.body(name, s.certs[name]))
}

func (s *Server) body(name string, current stored) map[string]any {
	return map[string]any{
		"id": fmt.Sprintf("%s/certificates/%s/%s", s.http.URL, name, current.version),
		// Key Vault encodes the thumbprint as base64url, which is what the SDK
		// decodes back into X509Thumbprint.
		"x5t":  base64.RawURLEncoding.EncodeToString(current.thumbprint),
		"tags": current.tags,
		"attributes": map[string]any{
			"enabled": true,
			"exp":     current.notAfter.Unix(),
		},
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func pemEncode(der []byte) []byte {
	const header = "-----BEGIN CERTIFICATE-----\n"
	const footer = "-----END CERTIFICATE-----\n"
	encoded := base64.StdEncoding.EncodeToString(der)
	var out strings.Builder
	out.WriteString(header)
	for len(encoded) > 64 {
		out.WriteString(encoded[:64])
		out.WriteString("\n")
		encoded = encoded[64:]
	}
	out.WriteString(encoded)
	out.WriteString("\n")
	out.WriteString(footer)
	return []byte(out.String())
}

// serveEntra answers the Microsoft Entra endpoints the credential needs before
// it can present a bearer token. Serving them here means the workload identity
// credential really runs -- assertion, discovery and token request included --
// rather than the test pretending authentication happened.
func (s *Server) serveEntra(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path

	switch {
	case strings.Contains(path, "/discovery/instance"):
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_discovery_endpoint": fmt.Sprintf("https://%s/%s/v2.0/.well-known/openid-configuration",
				AuthorityHost, TenantID),
			"api-version": "1.1",
			"metadata": []map[string]any{{
				"preferred_network": AuthorityHost,
				"preferred_cache":   AuthorityHost,
				"aliases":           []string{AuthorityHost},
			}},
		})
		return true

	case strings.HasSuffix(path, "/.well-known/openid-configuration"):
		issuer := fmt.Sprintf("https://%s/%s/v2.0", AuthorityHost, TenantID)
		writeJSON(w, http.StatusOK, map[string]any{
			"token_endpoint":                        fmt.Sprintf("https://%s/%s/oauth2/v2.0/token", AuthorityHost, TenantID),
			"authorization_endpoint":                fmt.Sprintf("https://%s/%s/oauth2/v2.0/authorize", AuthorityHost, TenantID),
			"issuer":                                issuer,
			"jwks_uri":                              fmt.Sprintf("https://%s/%s/discovery/v2.0/keys", AuthorityHost, TenantID),
			"response_modes_supported":              []string{"query", "fragment", "form_post"},
			"response_types_supported":              []string{"code", "token"},
			"subject_types_supported":               []string{"pairwise"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"tenant_region_scope":                   "EU",
			"cloud_instance_name":                   "microsoftonline.com",
			"cloud_graph_host_name":                 "graph.windows.net",
		})
		return true

	case strings.HasSuffix(path, "/oauth2/v2.0/token"):
		s.mu.Lock()
		s.tokenGrants++
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"token_type":     "Bearer",
			"expires_in":     3600,
			"ext_expires_in": 3600,
			"access_token":   "fake-access-token",
		})
		return true

	case strings.HasSuffix(path, "/discovery/v2.0/keys"):
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}})
		return true
	}
	return false
}

// selfSigned builds a certificate valid for the given hostnames. It is its own
// issuer, so the test can hand exactly this certificate to the operator as its
// trust root via SSL_CERT_FILE.
func selfSigned(hosts ...string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0]},
		DNSNames:              hosts,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: template}, nil
}
