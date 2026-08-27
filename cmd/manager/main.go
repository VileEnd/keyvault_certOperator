// Command manager runs the keyvault-cert-operator control loops.
//
// This file is the composition root: it is the only place that knows about the
// domain, the use cases, the adapters and Kubernetes all at once. Everything it
// wires together depends inwards only.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strings"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/controller"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/azure"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/kube"
)

var (
	scheme = runtime.NewScheme()
	setup  = ctrl.Log.WithName("setup")
)

func init() {
	utilRuntimeMust(clientgoscheme.AddToScheme(scheme))
	utilRuntimeMust(v1alpha1.AddToScheme(scheme))
	utilRuntimeMust(cmapi.AddToScheme(scheme))
	utilRuntimeMust(gatewayv1.Install(scheme))
}

type options struct {
	metricsAddr     string
	probeAddr       string
	secureMetrics   bool
	enableHTTP2     bool
	leaderElection  bool
	watchNamespaces string
	credentialMode  string
}

func main() {
	if err := run(); err != nil {
		setup.Error(err, "the operator exited with an error")
		os.Exit(1)
	}
}

func run() error {
	var opts options
	flag.StringVar(&opts.metricsAddr, "metrics-bind-address", "0",
		"Address the metrics endpoint binds to. \"0\" disables it.")
	flag.StringVar(&opts.probeAddr, "health-probe-bind-address", ":8081",
		"Address the health probe endpoint binds to.")
	flag.BoolVar(&opts.secureMetrics, "metrics-secure", true,
		"Serve metrics over HTTPS with authentication and authorization.")
	flag.BoolVar(&opts.enableHTTP2, "enable-http2", false,
		"Enable HTTP/2 on the metrics and webhook servers. Off by default to avoid the "+
			"HTTP/2 rapid-reset denial-of-service vectors.")
	flag.BoolVar(&opts.leaderElection, "leader-elect", false,
		"Enable leader election, so only one replica reconciles at a time.")
	flag.StringVar(&opts.watchNamespaces, "watch-namespaces", "",
		"Comma-separated namespaces to restrict the cache to. Empty means all namespaces.")
	flag.StringVar(&opts.credentialMode, "azure-credential", string(azure.CredentialWorkloadIdentity),
		"How to authenticate to Azure: workload-identity (default) or default (local development only).")

	zapOpts := zap.Options{Development: false}
	zapOpts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))
	ctx := ctrl.SetupSignalHandler()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions(opts))
	if err != nil {
		return fmt.Errorf("creating the manager: %w", err)
	}

	credential, err := azure.NewCredential(azure.CredentialMode(opts.credentialMode))
	if err != nil {
		return err
	}
	vault := azure.NewRepository(azure.NewClientFactory(credential, nil))
	clock := app.RealClock{}

	if err := (&controller.KeyVaultCertificateSyncReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorder("keyvaultcertificatesync"),
		Source:   kube.NewSecretSource(mgr.GetClient()),
		Vault:    vault,
		Clock:    clock,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setting up the certificate sync controller: %w", err)
	}

	// The HTTPRoute watch has to be decided here, before the manager starts:
	// controller-runtime cannot open an informer for a type the API server does
	// not serve. Installing Gateway API later therefore needs a restart, which
	// is documented. cert-manager, by contrast, is probed on every reconcile.
	watches := []client.Object{&networkingv1.Ingress{}}
	httpRoutes := crdInstalled(mgr.GetRESTMapper(),
		schema.GroupKind{Group: gatewayv1.GroupName, Kind: "HTTPRoute"}, gatewayv1.GroupVersion.Version)
	if httpRoutes {
		watches = append(watches, &gatewayv1.HTTPRoute{})
	}
	// Gateways are probed separately from HTTPRoutes. They are normally
	// installed together, but the listener hostnames are the only source that
	// sees a route which inherits its hostname instead of stating one, so
	// losing them silently would be the difference between discovering a
	// wildcard and discovering nothing.
	gateways := crdInstalled(mgr.GetRESTMapper(),
		schema.GroupKind{Group: gatewayv1.GroupName, Kind: "Gateway"}, gatewayv1.GroupVersion.Version)
	if gateways {
		watches = append(watches, &gatewayv1.Gateway{})
	}
	switch {
	case httpRoutes && gateways:
		setup.Info("Gateway API detected; discovering Gateway listener and HTTPRoute hostnames")
	case httpRoutes || gateways:
		setup.Info("Gateway API only partially present; discovery may be incomplete",
			"httpRoutes", httpRoutes, "gateways", gateways)
	default:
		setup.Info("Gateway API not detected; discovering hostnames from Ingress only. " +
			"Restart the operator after installing Gateway API to pick up Gateways and HTTPRoutes.")
	}

	if err := (&controller.WildcardCertificatePolicyReconciler{
		Client:              mgr.GetClient(),
		Scheme:              mgr.GetScheme(),
		Recorder:            mgr.GetEventRecorder("wildcardcertificatepolicy"),
		Certificates:        kube.NewCertificateWriter(mgr.GetClient(), mgr.GetRESTMapper()),
		Clock:               clock,
		HTTPRoutesAvailable: httpRoutes,
		GatewaysAvailable:   gateways,
	}).SetupWithManager(mgr, watches); err != nil {
		return fmt.Errorf("setting up the wildcard policy controller: %w", err)
	}

	// Neither probe reaches out to Azure. Making liveness depend on Key Vault
	// would turn an Azure outage into a CrashLoopBackOff, losing leader election
	// for a dependency the operator cannot influence.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("adding the health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("adding the readiness check: %w", err)
	}

	setup.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("running the manager: %w", err)
	}
	return nil
}

func managerOptions(opts options) ctrl.Options {
	var tlsOpts []func(*tls.Config)
	if !opts.enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} })
	}

	metricsOptions := metricsserver.Options{
		BindAddress:   opts.metricsAddr,
		SecureServing: opts.secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if opts.secureMetrics {
		metricsOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	return ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsOptions,
		HealthProbeBindAddress: opts.probeAddr,
		LeaderElection:         opts.leaderElection,
		LeaderElectionID:       "keyvault-certoperator.certsync.vileend.io",
		Cache:                  cacheOptions(opts),
	}
}

// cacheOptions restricts what the operator ever holds in memory.
//
// The Secret cache is limited to objects carrying the managed label. This is the
// single most valuable control here: it is what the API server is asked to
// watch, not a filter applied afterwards, so the operator never receives -- let
// alone caches -- the private keys of Secrets that are none of its business. The
// same selector is mirrored in the controller's watch predicate.
func cacheOptions(opts options) cache.Options {
	options := cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {
				Label:     controller.ManagedSecretSelector(),
				Transform: cache.TransformStripManagedFields(),
			},
		},
		DefaultTransform: cache.TransformStripManagedFields(),
	}

	if namespaces := splitNamespaces(opts.watchNamespaces); len(namespaces) > 0 {
		options.DefaultNamespaces = make(map[string]cache.Config, len(namespaces))
		for _, namespace := range namespaces {
			options.DefaultNamespaces[namespace] = cache.Config{}
		}
	}
	return options
}

// crdInstalled reports whether the API server serves a given kind.
func crdInstalled(mapper meta.RESTMapper, gk schema.GroupKind, version string) bool {
	_, err := mapper.RESTMapping(gk, version)
	return err == nil
}

func splitNamespaces(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func utilRuntimeMust(err error) {
	if err != nil {
		panic(err)
	}
}
