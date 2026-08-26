//go:build e2e

// Package e2e runs the operator as a real, separately-built binary against a
// real Kubernetes API server, authenticating as its own ServiceAccount and
// talking to a real HTTPS Key Vault endpoint.
//
// This covers what envtest structurally cannot:
//
//   - The generated ClusterRole is genuinely sufficient. envtest reconcilers run
//     with admin credentials, so an RBAC gap is invisible there and shows up
//     only in production. Here the operator holds nothing but its ServiceAccount
//     token.
//   - The Azure SDK request is well formed over the wire: TLS, the challenge
//     policy, base64 encoding, the certificate policy shape, tags and the
//     content type. The fake vault parses every upload as PKCS#12, so an archive
//     Key Vault would reject fails here too.
//   - main.go actually wires up and runs, including the label-scoped cache.
package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/testutil"
	"github.com/VileEnd/keyvault_certOperator/test/e2e/fakekeyvault"
)

const (
	certNamespace = "e2e-certs"
	appNamespace  = "e2e-apps"
)

type harness struct {
	client client.Client
	vault  *fakekeyvault.Server
}

func setup(t *testing.T) *harness {
	t.Helper()

	kubeconfig := os.Getenv("E2E_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("E2E_KUBECONFIG is unset; run 'make e2e' to start a cluster and set it")
	}

	scheme := runtime.NewScheme()
	mustSucceed(t, clientgoscheme.AddToScheme(scheme))
	mustSucceed(t, v1alpha1.AddToScheme(scheme))
	mustSucceed(t, cmapi.AddToScheme(scheme))
	mustSucceed(t, gatewayv1.Install(scheme))

	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("loading kubeconfig: %v", err)
	}
	// The test itself drives the cluster with admin rights; the operator under
	// test is the one restricted to its ServiceAccount.
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("building client: %v", err)
	}

	// Bound to 127.0.0.1:443 under a real *.vault.azure.net name, because the
	// Key Vault SDK verifies the challenge resource against the vault host and
	// that comparison includes any non-default port. Running it this way
	// exercises the real challenge verification instead of disabling it.
	vault, err := fakekeyvault.NewOnPort443()
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:443 for the fake vault (needs root and a free port): %v", err)
	}
	t.Cleanup(vault.Close)

	h := &harness{client: c, vault: vault}
	h.ensureNamespaces(t)
	h.startOperator(t)
	return h
}

func (h *harness) ensureNamespaces(t *testing.T) {
	t.Helper()
	for _, name := range []string{certNamespace, appNamespace} {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if err := h.client.Create(t.Context(), ns); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("creating namespace %s: %v", name, err)
		}
	}
}

// startOperator builds and runs the real manager binary, restricted to the
// ServiceAccount kubeconfig the harness script produced.
func (h *harness) startOperator(t *testing.T) {
	t.Helper()

	binary := os.Getenv("E2E_OPERATOR_BIN")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "manager")
		build := exec.Command("go", "build", "-o", binary, "../../cmd/manager")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("building the manager: %v\n%s", err, out)
		}
	}

	operatorKubeconfig := os.Getenv("E2E_OPERATOR_KUBECONFIG")
	if operatorKubeconfig == "" {
		t.Fatal("E2E_OPERATOR_KUBECONFIG is unset; it must point at the ServiceAccount-scoped kubeconfig")
	}

	// The client must trust the fake vault. Go honours SSL_CERT_FILE, so no
	// production code path is altered to make this work.
	caFile := filepath.Join(t.TempDir(), "vault-ca.pem")
	if err := os.WriteFile(caFile, h.vault.CACertPEM(), 0o600); err != nil {
		t.Fatalf("writing the vault CA: %v", err)
	}
	tokenFile := filepath.Join(t.TempDir(), "azure-token")
	if err := os.WriteFile(tokenFile, []byte("fake-federated-token"), 0o600); err != nil {
		t.Fatalf("writing the token file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary,
		"--metrics-bind-address=0",
		"--health-probe-bind-address=:18081",
		"--azure-credential=workload-identity",
	)
	cmd.Env = append(os.Environ(),
		"KUBECONFIG="+operatorKubeconfig,
		"SSL_CERT_FILE="+caFile,
		// Constructed by the workload identity credential at startup. The fake
		// vault never issues an auth challenge, so no token is ever redeemed.
		"AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000",
		"AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111",
		"AZURE_FEDERATED_TOKEN_FILE="+tokenFile,
		// Points the credential's token acquisition at the fake, so the workload
		// identity flow genuinely runs.
		"AZURE_AUTHORITY_HOST=https://"+fakekeyvault.AuthorityHost+"/",
		// Both fake hosts resolve to loopback, but Go decides whether to use a
		// proxy from the hostname rather than the resolved address, so they have
		// to be excluded explicitly or an ambient HTTPS_PROXY intercepts them.
		"NO_PROXY="+noProxy(),
		"no_proxy="+noProxy(),
	)
	logs := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the manager: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("operator logs:\n%s", logs.String())
		}
	})

	// Readiness proves the manager wired up and its caches synced -- which in
	// turn proves the ServiceAccount may list and watch everything it caches.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://127.0.0.1:18081/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			t.Fatalf("the manager exited during startup:\n%s", logs.String())
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("the manager did not become ready:\n%s", logs.String())
}

func TestOperatorSyncsACertificateIntoKeyVault(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	const certName = "wildcard-e2e-com"

	root := testutil.NewRootCA(t, "e2e root")
	inter := root.Intermediate(t, "e2e intermediate")
	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.e2e.com", "e2e.com"}})

	h.mustCreate(t, tlsSecret(t, "e2e-tls", leaf))
	sync := &v1alpha1.KeyVaultCertificateSync{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e", Namespace: certNamespace},
		Spec: v1alpha1.KeyVaultCertificateSyncSpec{
			Source:   v1alpha1.CertificateSourceSpec{SecretRef: v1alpha1.LocalSecretReference{Name: "e2e-tls"}},
			KeyVault: v1alpha1.KeyVaultSpec{VaultURL: h.vault.URL(), CertificateName: certName},
		},
	}
	h.mustCreate(t, sync)

	eventually(t, 90*time.Second, func() error {
		var got v1alpha1.KeyVaultCertificateSync
		if err := h.client.Get(ctx, client.ObjectKeyFromObject(sync), &got); err != nil {
			return err
		}
		condition := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionReady)
		if condition == nil || condition.Status != metav1.ConditionTrue {
			return fmt.Errorf("Ready = %+v", condition)
		}
		return nil
	})

	imports := h.vault.Imports()
	if len(imports) != 1 {
		t.Fatalf("imports = %d, want 1", len(imports))
	}
	imported := imports[0]

	// Everything below travelled over real HTTPS through the real Azure SDK.
	if imported.ContentType != app.ContentTypePKCS12 {
		t.Errorf("content type = %q, want %q", imported.ContentType, app.ContentTypePKCS12)
	}
	if !imported.Leaf.Equal(leaf.Cert) {
		t.Error("the uploaded leaf is not the certificate from the Secret")
	}
	// Application Gateway needs the intermediates; a leaf-only upload is one of
	// the documented causes of certificate failures.
	if len(imported.Chain) != 1 || !imported.Chain[0].Equal(inter.Cert) {
		t.Errorf("chain = %d certificates, want the intermediate", len(imported.Chain))
	}
	if imported.Tags[app.TagManagedBy] != app.TagManagedByValue {
		t.Errorf("managed-by tag = %q", imported.Tags[app.TagManagedBy])
	}
	if imported.Tags[app.TagChainDigest] == "" {
		t.Error("the chain digest tag is missing; intermediate rotation would go undetected")
	}
	// Key Vault answers an unauthenticated request with a challenge, so a
	// successful import proves the credential acquired and presented a token.
	if h.vault.TokenGrants() == 0 {
		t.Error("no access token was issued; the request somehow bypassed authentication")
	}

	// The versionless identifier is what an Application Gateway listener needs.
	var ready v1alpha1.KeyVaultCertificateSync
	if err := h.client.Get(ctx, client.ObjectKeyFromObject(sync), &ready); err != nil {
		t.Fatalf("re-reading the sync: %v", err)
	}
	want := h.vault.URL() + "/secrets/" + certName
	if ready.Status.SecretIdentifier != want {
		t.Errorf("secretIdentifier = %q, want %q", ready.Status.SecretIdentifier, want)
	}

	// Steady state: repeated reconciles must not mint further Key Vault versions.
	for i := range 3 {
		mustRetry(t, func() error {
			var current v1alpha1.KeyVaultCertificateSync
			if err := h.client.Get(ctx, client.ObjectKeyFromObject(sync), &current); err != nil {
				return err
			}
			if current.Annotations == nil {
				current.Annotations = map[string]string{}
			}
			current.Annotations["e2e/nudge"] = fmt.Sprint(i)
			return h.client.Update(ctx, &current)
		})
	}
	consistently(t, 5*time.Second, func() error {
		if n := h.vault.ImportCount(certName); n != 1 {
			return fmt.Errorf("imports = %d, want it to stay at 1", n)
		}
		return nil
	})

	// A renewal rewrites the same Secret and must produce exactly one more.
	renewed := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.e2e.com", "e2e.com"}})
	mustRetry(t, func() error {
		var secret corev1.Secret
		key := client.ObjectKey{Namespace: certNamespace, Name: "e2e-tls"}
		if err := h.client.Get(ctx, key, &secret); err != nil {
			return err
		}
		secret.Data[corev1.TLSCertKey] = renewed.CertPEM(t)
		secret.Data[corev1.TLSPrivateKeyKey] = renewed.KeyPEM(t, testutil.PKCS8)
		return h.client.Update(ctx, &secret)
	})

	eventually(t, 90*time.Second, func() error {
		if n := h.vault.ImportCount(certName); n != 2 {
			return fmt.Errorf("imports = %d, want 2 after renewal", n)
		}
		return nil
	})
}

func TestOperatorDiscoversHostsAndRequestsCertificates(t *testing.T) {
	h := setup(t)
	ctx := t.Context()

	h.mustCreate(t, &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: appNamespace},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{
			{Host: "api.discover.com"}, {Host: "discover.com"}, {Host: "nope.elsewhere.com"},
		}},
	})

	policy := &v1alpha1.WildcardCertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-discovery"},
		Spec: v1alpha1.WildcardCertificatePolicySpec{
			Zones:                []string{"discover.com"},
			MaxCertificates:      5,
			Grouping:             v1alpha1.GroupingPerZone,
			IssuerRef:            v1alpha1.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: certNamespace,
			KeyVault:             v1alpha1.KeyVaultSpec{VaultURL: h.vault.URL()},
		},
	}
	h.mustCreate(t, policy)
	t.Cleanup(func() { _ = h.client.Delete(context.Background(), policy) })

	// Creating a cert-manager Certificate exercises a cross-API write that the
	// ServiceAccount must be permitted to make.
	eventually(t, 90*time.Second, func() error {
		var cert cmapi.Certificate
		key := client.ObjectKey{Namespace: certNamespace, Name: "wildcard-discover-com"}
		if err := h.client.Get(ctx, key, &cert); err != nil {
			return err
		}
		want := []string{"*.discover.com", "discover.com"}
		got := slices.Clone(cert.Spec.DNSNames)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			return fmt.Errorf("dnsNames = %v, want %v", got, want)
		}
		return nil
	})

	eventually(t, 60*time.Second, func() error {
		var got v1alpha1.WildcardCertificatePolicy
		if err := h.client.Get(ctx, client.ObjectKeyFromObject(policy), &got); err != nil {
			return err
		}
		if got.Status.ApplicationGateway == nil || len(got.Status.ApplicationGateway.Listeners) != 1 {
			return fmt.Errorf("applicationGateway = %+v", got.Status.ApplicationGateway)
		}
		if !slices.ContainsFunc(got.Status.SkippedHosts, func(h v1alpha1.SkippedHost) bool {
			return h.Host == "nope.elsewhere.com"
		}) {
			return fmt.Errorf("skippedHosts = %+v, want the out-of-zone host reported", got.Status.SkippedHosts)
		}
		return nil
	})
}

// The Envoy Gateway shape: one wildcard listener fronting routes that state no
// hostnames of their own. A route with an empty spec.hostnames inherits
// everything its listener allows, so the hostname exists only on the Gateway --
// read HTTPRoutes alone and this cluster looks like it routes nothing.
//
// Run against a real API server because that is where it can actually break:
// the Gateway watch is established only if the CRD is served at startup, and
// listing Gateways needs an RBAC rule the operator's ServiceAccount really has
// to hold.
func TestOperatorDiscoversHostsFromGatewayListeners(t *testing.T) {
	h := setup(t)
	ctx := t.Context()

	wildcard := gatewayv1.Hostname("*.gwzone.com")
	apex := gatewayv1.Hostname("gwzone.com")
	outside := gatewayv1.Hostname("*.elsewhere.com")
	h.mustCreate(t, &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "eg", Namespace: appNamespace},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "envoy-gateway",
			Listeners: []gatewayv1.Listener{
				// Plain HTTP on purpose: Application Gateway terminates TLS
				// upstream, so the in-cluster listener has no certificate of its
				// own. The hostname is still a hostname the cluster routes.
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: &wildcard},
				{Name: "apex", Port: 8080, Protocol: gatewayv1.HTTPProtocolType, Hostname: &apex},
				{Name: "other", Port: 8081, Protocol: gatewayv1.HTTPProtocolType, Hostname: &outside},
				// No hostname: matches everything, so there is nothing concrete
				// to derive a certificate from and it must contribute nothing.
				{Name: "catchall", Port: 8082, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	})

	// Deliberately no hostnames: this route serves whatever the listener allows.
	h.mustCreate(t, &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "inherits", Namespace: appNamespace},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "eg"}},
			},
		},
	})

	policy := &v1alpha1.WildcardCertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-gateway"},
		Spec: v1alpha1.WildcardCertificatePolicySpec{
			Zones:                []string{"gwzone.com"},
			MaxCertificates:      5,
			Grouping:             v1alpha1.GroupingPerZone,
			IssuerRef:            v1alpha1.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: certNamespace,
			KeyVault:             v1alpha1.KeyVaultSpec{VaultURL: h.vault.URL()},
		},
	}
	h.mustCreate(t, policy)
	t.Cleanup(func() { _ = h.client.Delete(context.Background(), policy) })

	eventually(t, 90*time.Second, func() error {
		var cert cmapi.Certificate
		key := client.ObjectKey{Namespace: certNamespace, Name: "wildcard-gwzone-com"}
		if err := h.client.Get(ctx, key, &cert); err != nil {
			return err
		}
		want := []string{"*.gwzone.com", "gwzone.com"}
		got := slices.Clone(cert.Spec.DNSNames)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			return fmt.Errorf("dnsNames = %v, want %v", got, want)
		}
		return nil
	})

	eventually(t, 60*time.Second, func() error {
		var got v1alpha1.WildcardCertificatePolicy
		if err := h.client.Get(ctx, client.ObjectKeyFromObject(policy), &got); err != nil {
			return err
		}
		// The out-of-zone listener is reported, not silently dropped, and the
		// hostname-less listener contributes nothing at all.
		if !slices.ContainsFunc(got.Status.SkippedHosts, func(s v1alpha1.SkippedHost) bool {
			return s.Host == "*.elsewhere.com"
		}) {
			return fmt.Errorf("skippedHosts = %+v, want the out-of-zone listener reported", got.Status.SkippedHosts)
		}
		for _, skipped := range got.Status.SkippedHosts {
			if skipped.Host == "" {
				return fmt.Errorf("the hostname-less listener produced an empty host: %+v", got.Status.SkippedHosts)
			}
		}
		// Exactly one certificate: the catch-all listener contributed nothing,
		// so it cannot have planted a nameless certificate alongside the zone.
		if len(got.Status.RequiredCertificates) != 1 {
			return fmt.Errorf("requiredCertificates = %+v, want exactly one", got.Status.RequiredCertificates)
		}
		return nil
	})
}

// noProxy keeps the fake vault and login hosts off any ambient HTTPS proxy,
// preserving whatever exclusions the environment already sets.
func noProxy() string {
	existing := os.Getenv("NO_PROXY")
	if existing == "" {
		existing = os.Getenv("no_proxy")
	}
	hosts := fakekeyvault.VaultHost + "," + fakekeyvault.AuthorityHost + ",127.0.0.1,localhost"
	if existing != "" {
		return hosts + "," + existing
	}
	return hosts
}

func (h *harness) mustCreate(t *testing.T, obj client.Object) {
	t.Helper()
	if err := h.client.Create(t.Context(), obj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("creating %T %s: %v", obj, obj.GetName(), err)
	}
}

func tlsSecret(t *testing.T, name string, leaf *testutil.Leaf) *corev1.Secret {
	t.Helper()
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: certNamespace,
			Labels:    map[string]string{v1alpha1.LabelManaged: v1alpha1.LabelManagedValue},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       leaf.CertPEM(t),
			corev1.TLSPrivateKeyKey: leaf.KeyPEM(t, testutil.PKCS8),
		},
	}
}

func mustRetry(t *testing.T, fn func() error) {
	t.Helper()
	if err := retry.RetryOnConflict(retry.DefaultRetry, fn); err != nil {
		t.Fatalf("update: %v", err)
	}
}

func mustSucceed(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
}

func eventually(t *testing.T, timeout time.Duration, check func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if last = check(); last == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %v", timeout, last)
}

func consistently(t *testing.T, window time.Duration, check func() error) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if err := check(); err != nil {
			t.Fatalf("condition stopped holding: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
