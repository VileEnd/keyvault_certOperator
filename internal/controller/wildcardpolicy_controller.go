package controller

import (
	"context"
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/azure"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/kube"
)

// maxReportedSkippedHosts bounds the skipped-host sample kept in status. A large
// cluster can route thousands of hostnames, and an unbounded status field would
// put all of them into etcd on every reconcile. The full count is reported
// alongside the sample.
const maxReportedSkippedHosts = 50

// DefaultDiscoveryInterval is how often discovery re-runs without an event.
const DefaultDiscoveryInterval = 10 * time.Minute

// WildcardCertificatePolicyReconciler discovers the hostnames the cluster
// routes, has cert-manager issue the wildcards that cover them, and generates
// the sync resources that push those into Key Vault.
type WildcardCertificatePolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	Certificates *kube.CertificateWriter
	Clock        app.Clock

	// HTTPRoutesAvailable records whether the Gateway API CRDs were present at
	// startup. The watch cannot be established for an unknown type, so enabling
	// Gateway API afterwards needs an operator restart.
	HTTPRoutesAvailable bool
	// GatewaysAvailable records the same for the Gateway kind.
	GatewaysAvailable bool
}

// +kubebuilder:rbac:groups=certsync.vileend.io,resources=wildcardcertificatepolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certsync.vileend.io,resources=wildcardcertificatepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certsync.vileend.io,resources=wildcardcertificatepolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete

// Reconcile runs one discovery and issuance pass.
func (r *WildcardCertificatePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var policy v1alpha1.WildcardCertificatePolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !policy.DeletionTimestamp.IsZero() {
		// Generated Certificates and sync resources are owner-referenced, so the
		// garbage collector removes them. Key Vault is never touched.
		if controllerutil.RemoveFinalizer(&policy, v1alpha1.FinalizerName) {
			if err := r.Update(ctx, &policy); err != nil {
				return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
			}
		}
		certificatesRequired.DeleteLabelValues(policy.Name)
		hostsSkipped.DeleteLabelValues(policy.Name)
		return ctrl.Result{}, nil
	}

	if controllerutil.AddFinalizer(&policy, v1alpha1.FinalizerName) {
		if err := r.Update(ctx, &policy); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
	}

	state, err := r.plan(ctx, &policy)
	if err != nil {
		reason, retryable := classify(err)
		log.Error(err, "discovery failed", "reason", reason)
		setFalse(&policy.Status.Conditions, v1alpha1.ConditionDiscovered, ReasonDiscoveryFailed, err.Error(), policy.Generation)
		setFalse(&policy.Status.Conditions, v1alpha1.ConditionReady, reason, err.Error(), policy.Generation)
		r.event(&policy, corev1.EventTypeWarning, ReasonDiscoveryFailed, "Discover", err.Error())
		if statusErr := r.updateStatus(ctx, &policy); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		if retryable {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: jitter(DefaultDiscoveryInterval)}, nil
	}

	r.recordPlan(&policy, state)

	available, err := r.Certificates.Available(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !available {
		// Degrade loudly rather than fail: the required certificates are still
		// reported, so the plan is visible even before cert-manager is installed.
		const msg = "the cert-manager Certificate CRD is not installed, so no certificates can be issued; " +
			"status.requiredCertificates still reports what this policy would create"
		setFalse(&policy.Status.Conditions, v1alpha1.ConditionCertManagerAvailable, ReasonCertManagerMissing, msg, policy.Generation)
		setFalse(&policy.Status.Conditions, v1alpha1.ConditionReady, ReasonCertManagerMissing, msg, policy.Generation)
		r.event(&policy, corev1.EventTypeWarning, ReasonCertManagerMissing, "Issue", msg)
		if err := r.updateStatus(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: jitter(DefaultDiscoveryInterval)}, nil
	}
	setTrue(&policy.Status.Conditions, v1alpha1.ConditionCertManagerAvailable, ReasonCertManagerFound,
		"cert-manager is installed", policy.Generation)

	if err := r.apply(ctx, &policy, state); err != nil {
		setFalse(&policy.Status.Conditions, v1alpha1.ConditionReady, ReasonIssuanceFailed, err.Error(), policy.Generation)
		r.event(&policy, corev1.EventTypeWarning, ReasonIssuanceFailed, "Issue", err.Error())
		if statusErr := r.updateStatus(ctx, &policy); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{}, err
	}

	orphans, err := r.handleOrphans(ctx, &policy, state)
	if err != nil {
		return ctrl.Result{}, err
	}

	message := fmt.Sprintf("%d certificate(s) required from %d discovered hostname(s)",
		len(state.Certificates), len(state.DiscoveredHosts))
	if orphans > 0 {
		message += fmt.Sprintf("; %d no longer required and %s",
			orphans, orphanVerb(policy.Spec.OrphanPolicy))
	}
	setTrue(&policy.Status.Conditions, v1alpha1.ConditionDiscovered, ReasonSynced, message, policy.Generation)
	setTrue(&policy.Status.Conditions, v1alpha1.ConditionReady, ReasonSynced, message, policy.Generation)

	if err := r.updateStatus(ctx, &policy); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: jitter(DefaultDiscoveryInterval)}, nil
}

func (r *WildcardCertificatePolicyReconciler) plan(
	ctx context.Context, policy *v1alpha1.WildcardCertificatePolicy,
) (app.DesiredState, error) {
	vaultURL, err := azure.VaultURL(vaultTarget(policy.Spec.KeyVault), azure.Cloud(policy.Spec.KeyVault.Cloud))
	if err != nil {
		return app.DesiredState{}, fmt.Errorf("%w: %w", domain.ErrInvalidVaultName, err)
	}

	discovery := policy.Spec.Discovery
	selector, err := kube.SelectorFrom(namespaceSelector(discovery))
	if err != nil {
		return app.DesiredState{}, fmt.Errorf("%w: %w", domain.ErrInvalidZone, err)
	}

	hosts := &kube.HostSource{
		Reader:            r.Client,
		IncludeIngress:    enabled(discovery, func(d *v1alpha1.DiscoverySpec) *bool { return d.Ingress }),
		IncludeHTTPRoutes: r.HTTPRoutesAvailable && enabled(discovery, func(d *v1alpha1.DiscoverySpec) *bool { return d.HTTPRoutes }),
		IncludeGateways:   r.GatewaysAvailable && enabled(discovery, func(d *v1alpha1.DiscoverySpec) *bool { return d.Gateways }),
		NamespaceSelector: selector,
	}

	return app.NewPlanner(hosts).Plan(ctx, app.PolicySpec{
		Zones:           policy.Spec.Zones,
		MaxCertificates: int(policy.Spec.MaxCertificates),
		Grouping:        domain.Grouping(policy.Spec.Grouping),
		VaultURL:        vaultURL,
	})
}

// apply creates the cert-manager Certificate and the sync resource for each
// planned certificate.
func (r *WildcardCertificatePolicyReconciler) apply(
	ctx context.Context, policy *v1alpha1.WildcardCertificatePolicy, state app.DesiredState,
) error {
	for _, cert := range state.Certificates {
		if err := r.Certificates.Ensure(ctx, policy, kube.CertificateRequest{
			Name:       cert.Name,
			Namespace:  policy.Spec.CertificateNamespace,
			SecretName: cert.SecretName,
			DNSNames:   cert.DNSNames,
			IssuerRef: cmmeta.IssuerReference{
				Name:  policy.Spec.IssuerRef.Name,
				Kind:  policy.Spec.IssuerRef.Kind,
				Group: policy.Spec.IssuerRef.Group,
			},
			PolicyName: policy.Name,
		}); err != nil {
			return err
		}
		if err := r.ensureSync(ctx, policy, cert); err != nil {
			return err
		}
	}
	return nil
}

func (r *WildcardCertificatePolicyReconciler) ensureSync(
	ctx context.Context, policy *v1alpha1.WildcardCertificatePolicy, cert app.DesiredCertificate,
) error {
	sync := &v1alpha1.KeyVaultCertificateSync{
		ObjectMeta: metav1.ObjectMeta{Name: cert.Name, Namespace: policy.Spec.CertificateNamespace},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, sync, func() error {
		if sync.Labels == nil {
			sync.Labels = map[string]string{}
		}
		sync.Labels[v1alpha1.LabelPolicy] = policy.Name
		sync.Labels[v1alpha1.LabelCertificate] = cert.Name

		sync.Spec.Source.SecretRef.Name = cert.SecretName
		sync.Spec.KeyVault = policy.Spec.KeyVault
		sync.Spec.KeyVault.CertificateName = cert.Name
		sync.Spec.SyncPolicy = policy.Spec.SyncPolicy

		return controllerutil.SetControllerReference(policy, sync, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("ensuring sync resource %s/%s: %w", policy.Spec.CertificateNamespace, cert.Name, err)
	}
	return nil
}

// handleOrphans deals with resources this policy generated that the current
// plan no longer requires.
//
// Retain is the default and deliberately so. An Application Gateway listener may
// still be serving a certificate whose last Ingress just disappeared, and
// deleting it would take that listener down. Under either policy the Key Vault
// certificate itself is left alone.
func (r *WildcardCertificatePolicyReconciler) handleOrphans(
	ctx context.Context, policy *v1alpha1.WildcardCertificatePolicy, state app.DesiredState,
) (int, error) {
	wanted := make(map[string]struct{}, len(state.Certificates))
	for _, cert := range state.Certificates {
		wanted[cert.Name] = struct{}{}
	}

	selector := client.MatchingLabels{v1alpha1.LabelPolicy: policy.Name}
	inNamespace := client.InNamespace(policy.Spec.CertificateNamespace)

	var syncs v1alpha1.KeyVaultCertificateSyncList
	if err := r.List(ctx, &syncs, inNamespace, selector); err != nil {
		return 0, fmt.Errorf("listing generated sync resources: %w", err)
	}

	orphans := 0
	for i := range syncs.Items {
		item := &syncs.Items[i]
		if _, ok := wanted[item.Name]; ok {
			continue
		}
		orphans++
		if policy.Spec.OrphanPolicy != v1alpha1.OrphanPrune {
			continue
		}
		if err := r.Delete(ctx, item); err != nil && client.IgnoreNotFound(err) != nil {
			return orphans, fmt.Errorf("pruning sync resource %s: %w", item.Name, err)
		}
	}

	if policy.Spec.OrphanPolicy == v1alpha1.OrphanPrune {
		var certs cmapi.CertificateList
		if err := r.List(ctx, &certs, inNamespace, selector); err != nil {
			return orphans, fmt.Errorf("listing generated certificates: %w", err)
		}
		for i := range certs.Items {
			item := &certs.Items[i]
			if _, ok := wanted[item.Name]; ok {
				continue
			}
			if err := r.Delete(ctx, item); err != nil && client.IgnoreNotFound(err) != nil {
				return orphans, fmt.Errorf("pruning certificate %s: %w", item.Name, err)
			}
		}
	}
	return orphans, nil
}

func (r *WildcardCertificatePolicyReconciler) recordPlan(
	policy *v1alpha1.WildcardCertificatePolicy, state app.DesiredState,
) {
	now := metav1.NewTime(r.Clock.Now())
	policy.Status.ObservedGeneration = policy.Generation
	policy.Status.DiscoveredHosts = int32(len(state.DiscoveredHosts))
	policy.Status.SkippedHostCount = int32(len(state.Skipped))
	policy.Status.LastDiscoveryTime = &now

	policy.Status.RequiredCertificates = make([]v1alpha1.PlannedCertificate, 0, len(state.Certificates))
	listeners := make([]v1alpha1.ListenerGuidance, 0, len(state.Certificates))
	for _, cert := range state.Certificates {
		policy.Status.RequiredCertificates = append(policy.Status.RequiredCertificates, v1alpha1.PlannedCertificate{
			Name:             cert.Name,
			Zone:             cert.Zone,
			DNSNames:         cert.DNSNames,
			SecretName:       cert.SecretName,
			SecretIdentifier: cert.SecretIdentifier,
		})
		for _, group := range cert.Listeners {
			listeners = append(listeners, v1alpha1.ListenerGuidance{
				Hostnames:        group,
				KeyVaultSecretID: cert.SecretIdentifier,
			})
		}
	}

	// Emitted as data for Terraform or the CLI to apply. The operator holds no
	// ARM permissions and never writes gateway configuration itself.
	policy.Status.ApplicationGateway = &v1alpha1.ApplicationGatewayGuidance{Listeners: listeners}

	skipped := state.Skipped
	if len(skipped) > maxReportedSkippedHosts {
		skipped = skipped[:maxReportedSkippedHosts]
	}
	policy.Status.SkippedHosts = make([]v1alpha1.SkippedHost, 0, len(skipped))
	for _, host := range skipped {
		policy.Status.SkippedHosts = append(policy.Status.SkippedHosts,
			v1alpha1.SkippedHost{Host: host.Host, Reason: host.Reason})
	}

	certificatesRequired.WithLabelValues(policy.Name).Set(float64(len(state.Certificates)))
	hostsSkipped.WithLabelValues(policy.Name).Set(float64(len(state.Skipped)))
}

func (r *WildcardCertificatePolicyReconciler) updateStatus(
	ctx context.Context, policy *v1alpha1.WildcardCertificatePolicy,
) error {
	if err := r.Status().Update(ctx, policy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return nil
		}
		return fmt.Errorf("updating status: %w", err)
	}
	return nil
}

func (r *WildcardCertificatePolicyReconciler) event(obj *v1alpha1.WildcardCertificatePolicy,
	eventType, reason, action, note string,
) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(obj, nil, eventType, reason, action, "%s", note)
}

// SetupWithManager registers the controller and its discovery watches.
func (r *WildcardCertificatePolicyReconciler) SetupWithManager(mgr ctrl.Manager, watches []client.Object) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.WildcardCertificatePolicy{}).
		Named("wildcardcertificatepolicy").
		Owns(&v1alpha1.KeyVaultCertificateSync{})

	for _, obj := range watches {
		b = b.Watches(obj, r.enqueueAllPolicies())
	}
	return b.Complete(r)
}

// enqueueAllPolicies re-runs every policy on any routing change. Policies are a
// handful of cluster-scoped objects, so a full sweep is cheaper and simpler than
// working out which policy a given hostname might belong to.
func (r *WildcardCertificatePolicyReconciler) enqueueAllPolicies() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		var list v1alpha1.WildcardCertificatePolicyList
		if err := r.List(ctx, &list); err != nil {
			logf.FromContext(ctx).Error(err, "listing policies for a routing change")
			return nil
		}
		requests := make([]reconcile.Request, 0, len(list.Items))
		for i := range list.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(&list.Items[i]),
			})
		}
		return requests
	})
}

func namespaceSelector(discovery *v1alpha1.DiscoverySpec) *metav1.LabelSelector {
	if discovery == nil {
		return nil
	}
	return discovery.NamespaceSelector
}

// enabled defaults an optional boolean to true, matching the CRD defaults.
func enabled(discovery *v1alpha1.DiscoverySpec, pick func(*v1alpha1.DiscoverySpec) *bool) bool {
	if discovery == nil {
		return true
	}
	value := pick(discovery)
	return value == nil || *value
}

func orphanVerb(policy v1alpha1.OrphanPolicy) string {
	if policy == v1alpha1.OrphanPrune {
		return "pruned"
	}
	return "retained (the Key Vault certificate is never deleted)"
}
