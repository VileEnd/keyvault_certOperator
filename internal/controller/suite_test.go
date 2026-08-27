package controller_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/controller"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/kube"
)

var (
	testEnv    *envtest.Environment
	k8sClient  client.Client
	testScheme = runtime.NewScheme()
	testVault  *recordingVault
)

// recordingVault stands in for Azure Key Vault. It models the one behaviour the
// controllers must respect: an import always creates a new version, so the tests
// can assert that a steady-state reconcile performs none.
type recordingVault struct {
	mu      sync.Mutex
	stored  map[string]domain.VaultSnapshot
	imports map[string]int
}

func newRecordingVault() *recordingVault {
	return &recordingVault{stored: map[string]domain.VaultSnapshot{}, imports: map[string]int{}}
}

func (v *recordingVault) Snapshot(_ context.Context, ref app.VaultRef) (domain.VaultSnapshot, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	snapshot, ok := v.stored[ref.CertificateName]
	if !ok {
		return domain.VaultSnapshot{Exists: false}, nil
	}
	return snapshot, nil
}

func (v *recordingVault) Import(_ context.Context, ref app.VaultRef, req app.ImportRequest) (app.ImportResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.imports[ref.CertificateName]++
	version := fmt.Sprintf("v%d", v.imports[ref.CertificateName])
	v.stored[ref.CertificateName] = domain.VaultSnapshot{
		Exists:      true,
		Enabled:     true,
		Thumbprint:  []byte(req.Tags["test-thumbprint"]),
		ChainDigest: req.Tags[app.TagChainDigest],
	}
	return app.ImportResult{Version: version}, nil
}

// seed records a certificate as already present in the vault.
func (v *recordingVault) seed(name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.stored[name] = domain.VaultSnapshot{Exists: true, Enabled: true}
}

func (v *recordingVault) exists(name string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.stored[name]
	return ok
}

func (v *recordingVault) importCount(name string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.imports[name]
}

func TestMain(m *testing.M) {
	os.Exit(runSuite(m))
}

// envtestReady reports whether the API server came up. When it did not, the
// envtest-backed tests skip individually rather than the whole package silently
// reporting success -- the pure unit tests in this package still run.
var envtestReady bool

func runSuite(m *testing.M) int {
	assets, err := envTestAssets()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest binaries unavailable, running unit tests only: %v\n", err)
		return m.Run()
	}

	utilMust(clientgoscheme.AddToScheme(testScheme))
	utilMust(v1alpha1.AddToScheme(testScheme))
	utilMust(cmapi.AddToScheme(testScheme))

	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			filepath.Join("..", "..", "test", "testdata", "crds"),
		},
		ErrorIfCRDPathMissing: true,
		BinaryAssetsDirectory: assets,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "starting envtest: %v\n", err)
		return 1
	}
	envtestReady = true
	defer func() {
		if err := testEnv.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "stopping envtest: %v\n", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := startManager(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "starting manager: %v\n", err)
		return 1
	}

	return m.Run()
}

func startManager(ctx context.Context, cfg *rest.Config) error {
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  testScheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				// Mirrors production: only labelled Secrets are ever cached, so
				// the tests also prove an unlabelled Secret stays invisible.
				&corev1.Secret{}: {Label: controller.ManagedSecretSelector()},
			},
		},
	})
	if err != nil {
		return err
	}

	testVault = newRecordingVault()

	if err := (&controller.KeyVaultCertificateSyncReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorder("test-sync"),
		Source:   kube.NewSecretSource(mgr.GetClient()),
		Vault:    &tagRecordingVault{testVault},
		Clock:    app.RealClock{},
		// Every other test in this package targets my-vault, so enforcing the
		// allowlist here means they all double as proof that a permitted vault
		// still works.
		AllowedVaults: domain.VaultAllowlist{"https://my-vault.vault.azure.net"},
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := (&controller.WildcardCertificatePolicyReconciler{
		Client:              mgr.GetClient(),
		Scheme:              mgr.GetScheme(),
		Recorder:            mgr.GetEventRecorder("test-policy"),
		Certificates:        kube.NewCertificateWriter(mgr.GetClient(), mgr.GetRESTMapper()),
		Clock:               app.RealClock{},
		AllowedVaults:       domain.VaultAllowlist{"https://my-vault.vault.azure.net"},
		HTTPRoutesAvailable: false,
	}).SetupWithManager(mgr, []client.Object{&networkingv1.Ingress{}}); err != nil {
		return err
	}

	k8sClient = mgr.GetClient()

	go func() {
		if err := mgr.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "manager stopped: %v\n", err)
		}
	}()

	if !mgr.GetCache().WaitForCacheSync(ctx) {
		return fmt.Errorf("caches did not sync")
	}
	return nil
}

// tagRecordingVault records the leaf thumbprint alongside the import so the fake
// can answer a later Snapshot the way Key Vault would.
type tagRecordingVault struct{ *recordingVault }

func (v *tagRecordingVault) Import(ctx context.Context, ref app.VaultRef, req app.ImportRequest) (app.ImportResult, error) {
	// Recover the thumbprint from the encoded archive so the fake's stored state
	// matches what a real vault would report on the next read.
	if thumbprint, err := thumbprintOf(req); err == nil {
		if req.Tags == nil {
			req.Tags = map[string]string{}
		}
		req.Tags["test-thumbprint"] = thumbprint
	}
	return v.recordingVault.Import(ctx, ref, req)
}

func thumbprintOf(req app.ImportRequest) (string, error) {
	_, leaf, chain, err := decodePKCS12(req)
	if err != nil {
		return "", err
	}
	bundle := &domain.Bundle{Leaf: leaf, Chain: chain}
	return string(bundle.Thumbprint()), nil
}

func envTestAssets() (string, error) {
	if assets := os.Getenv("KUBEBUILDER_ASSETS"); assets != "" {
		return assets, nil
	}
	// Mirror the kubebuilder scaffold's fallback so the suite runs from an IDE.
	base := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(base)
	if err != nil {
		return "", fmt.Errorf("KUBEBUILDER_ASSETS is unset and %s is unreadable: %w", base, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(base, entry.Name()), nil
		}
	}
	return "", fmt.Errorf("no envtest binaries found under %s", base)
}

func utilMust(err error) {
	if err != nil {
		panic(err)
	}
}

// requireEnvtest skips a test that needs a live API server.
func requireEnvtest(t *testing.T) {
	t.Helper()
	if !envtestReady {
		t.Skip("envtest binaries unavailable; run 'make setup-envtest' to enable this test")
	}
}

// eventually retries check until it passes or the deadline expires. envtest runs
// against a real API server, so every assertion after a write is asynchronous.
func eventually(t *testing.T, timeout time.Duration, check func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		last = check()
		if last == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %v", timeout, last)
}

// consistently asserts check keeps passing for the whole window, which is how a
// "nothing further happened" claim is verified.
func consistently(t *testing.T, window time.Duration, check func() error) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if err := check(); err != nil {
			t.Fatalf("condition stopped holding: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
