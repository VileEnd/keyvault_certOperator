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

// These mirror the MaxItems on the status fields they bound. The API server
// rejects a status that exceeds them, and a rejected status update is not a
// cosmetic failure: the policy would report nothing at all, on every pass,
// forever. Verified against a real API server -- 101 listeners and 101 SANs are
// both refused.
const (
	maxReportedListeners = 100
	maxReportedDNSNames  = 100
)

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

	// Cloud is the Azure cloud the operator's identity lives in. It resolves a
	// bare vault name on any resource that does not name a cloud of its own.
	Cloud azure.Cloud

	// AllowedVaults bounds which Key Vaults this operator may write to. Empty
	// permits every vault, which is the behaviour that existed before the flag
	// and stays the default so an upgrade changes nothing on its own.
	AllowedVaults domain.VaultAllowlist
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

	// What already exists is read before planning, so the certificate cap can
	// overflow a new certificate rather than evict one the cluster is serving.
	existing, err := r.generatedCertificateNames(ctx, &policy)
	if err != nil {
		return ctrl.Result{}, err
	}

	state, err := r.plan(ctx, &policy, existing)
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
		// The plan is already computed and worth keeping: without this the
		// discovery result is thrown away on a transient mapper failure and the
		// policy reports the state from some earlier pass instead.
		if statusErr := r.updateStatus(ctx, &policy); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
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

	orphans, pruneWithheld, err := r.handleOrphans(ctx, &policy, state)
	if err != nil {
		return ctrl.Result{}, err
	}

	message := fmt.Sprintf("%d certificate(s) required from %d discovered hostname(s)",
		len(state.Certificates), len(state.DiscoveredHosts))
	if orphans > 0 {
		verb := orphanVerb(policy.Spec.OrphanPolicy)
		if pruneWithheld != "" {
			verb = "retained despite orphanPolicy: Prune"
		}
		message += fmt.Sprintf("; %d no longer required and %s", orphans, verb)
	}
	setTrue(&policy.Status.Conditions, v1alpha1.ConditionDiscovered, ReasonSynced, message, policy.Generation)

	// Withholding a prune leaves the cluster in a correct but unintended state,
	// so it is surfaced rather than logged: the resources are still there and
	// the operator is not going to remove them until the cause is addressed.
	if pruneWithheld != "" {
		withheldMsg := fmt.Sprintf("%s; %d orphaned resource(s) were kept rather than deleted because %s",
			message, orphans, pruneWithheld)
		setFalse(&policy.Status.Conditions, v1alpha1.ConditionReady, ReasonPruneWithheld, withheldMsg, policy.Generation)
		r.event(&policy, corev1.EventTypeWarning, ReasonPruneWithheld, "Prune", withheldMsg)
		if err := r.updateStatus(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: jitter(DefaultDiscoveryInterval)}, nil
	}

	setTrue(&policy.Status.Conditions, v1alpha1.ConditionReady, ReasonSynced, message, policy.Generation)

	if err := r.updateStatus(ctx, &policy); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: jitter(DefaultDiscoveryInterval)}, nil
}

// generatedCertificateNames lists the certificates this policy has already
// generated. It reads the sync resources rather than status.requiredCertificates
// because the question is what exists, not what was last planned.
func (r *WildcardCertificatePolicyReconciler) generatedCertificateNames(
	ctx context.Context, policy *v1alpha1.WildcardCertificatePolicy,
) ([]string, error) {
	var syncs v1alpha1.KeyVaultCertificateSyncList
	if err := r.List(ctx, &syncs,
		client.InNamespace(policy.Spec.CertificateNamespace),
		client.MatchingLabels{v1alpha1.LabelPolicy: policy.Name},
	); err != nil {
		return nil, fmt.Errorf("listing generated sync resources: %w", err)
	}
	names := make([]string, 0, len(syncs.Items))
	for i := range syncs.Items {
		names = append(names, syncs.Items[i].Name)
	}
	return names, nil
}

func (r *WildcardCertificatePolicyReconciler) plan(
	ctx context.Context, policy *v1alpha1.WildcardCertificatePolicy, existing []string,
) (app.DesiredState, error) {
	vaultURL, err := azure.VaultURL(vaultTarget(policy.Spec.KeyVault), vaultCloud(policy.Spec.KeyVault, r.Cloud))
	if err != nil {
		return app.DesiredState{}, fmt.Errorf("%w: %w", domain.ErrInvalidVaultName, err)
	}
	// Checked here as well as in the sync controller. Without it a policy would
	// happily issue certificates and generate sync resources that can only ever
	// fail, spending Let's Encrypt rate limit on a vault it may not write to.
	if !r.AllowedVaults.Permits(vaultURL) {
		return app.DesiredState{}, fmt.Errorf("%w: %q is not one of [%s]",
			domain.ErrVaultNotAllowed, vaultURL, r.AllowedVaults)
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
		Zones:              policy.Spec.Zones,
		MaxCertificates:    int(policy.Spec.MaxCertificates),
		Existing:           existing,
		Grouping:           domain.Grouping(policy.Spec.Grouping),
		IssueZoneWildcards: policy.Spec.IssueZoneWildcards,
		IssueZoneApex:      policy.Spec.IssueZoneApex,
		CertificateNames:   pinnedVaultNames(policy.Spec.CertificateNames),
		VaultURL:           vaultURL,
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
		// The sync resource itself keeps the derived name it was created under,
		// since renaming it would orphan the one already generated; only the Key
		// Vault object it writes follows a pin from spec.certificateNames.
		sync.Spec.KeyVault.CertificateName = cert.VaultName
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
) (int, string, error) {
	wanted := make(map[string]struct{}, len(state.Certificates))
	for _, cert := range state.Certificates {
		wanted[cert.Name] = struct{}{}
	}

	// Pruning is judged entirely against the current discovery pass, so it is
	// only safe when that pass can be trusted to be complete. A failed pass
	// never reaches here -- plan() returns early -- but a pass that succeeds
	// while seeing nothing is indistinguishable from one that is misconfigured,
	// and the destructive reading is the wrong default. Deleting a generated
	// Certificate destroys the issued Secret, so recovering costs a fresh
	// issuance against Let's Encrypt's duplicate-certificate limit.
	withheld := r.pruneWithheldReason(policy, state)
	pruning := policy.Spec.OrphanPolicy == v1alpha1.OrphanPrune && withheld == ""

	selector := client.MatchingLabels{v1alpha1.LabelPolicy: policy.Name}
	inNamespace := client.InNamespace(policy.Spec.CertificateNamespace)

	var syncs v1alpha1.KeyVaultCertificateSyncList
	if err := r.List(ctx, &syncs, inNamespace, selector); err != nil {
		return 0, "", fmt.Errorf("listing generated sync resources: %w", err)
	}

	orphans := 0
	for i := range syncs.Items {
		item := &syncs.Items[i]
		if _, ok := wanted[item.Name]; ok {
			continue
		}
		orphans++
		if !pruning {
			continue
		}
		if err := r.Delete(ctx, item); err != nil && client.IgnoreNotFound(err) != nil {
			return orphans, withheld, fmt.Errorf("pruning sync resource %s: %w", item.Name, err)
		}
	}

	if pruning {
		var certs cmapi.CertificateList
		if err := r.List(ctx, &certs, inNamespace, selector); err != nil {
			return orphans, withheld, fmt.Errorf("listing generated certificates: %w", err)
		}
		for i := range certs.Items {
			item := &certs.Items[i]
			if _, ok := wanted[item.Name]; ok {
				continue
			}
			if err := r.Delete(ctx, item); err != nil && client.IgnoreNotFound(err) != nil {
				return orphans, withheld, fmt.Errorf("pruning certificate %s: %w", item.Name, err)
			}
		}
	}

	// Nothing to withhold if nothing was orphaned in the first place.
	if orphans == 0 {
		withheld = ""
	}
	return orphans, withheld, nil
}

// pruneWithheldReason explains why pruning must not run, or "" when it may.
//
// Both cases refuse rather than trying to tell apart states that genuinely look
// identical from inside the operator.
func (r *WildcardCertificatePolicyReconciler) pruneWithheldReason(
	policy *v1alpha1.WildcardCertificatePolicy, state app.DesiredState,
) string {
	if policy.Spec.OrphanPolicy != v1alpha1.OrphanPrune {
		return ""
	}

	// A plan with nothing in it means either the cluster routes nothing at all
	// or discovery is misconfigured -- a namespaceSelector matching no
	// namespace, or every source switched off. Those are the same observation,
	// and one of them costs every issued certificate.
	if len(state.Certificates) == 0 {
		return "the discovery pass planned no certificates at all, which cannot be told apart " +
			"from a misconfiguration; set issueZoneWildcards to make the plan independent of discovery"
	}

	// A source the policy asked for but which the operator could not watch
	// makes the view partial by construction. Gateway API is the live case:
	// its watches are established only if the CRDs are served at startup, so a
	// restart before they are registered silently narrows discovery.
	discovery := policy.Spec.Discovery
	if !r.HTTPRoutesAvailable && explicitlyEnabled(discovery, func(d *v1alpha1.DiscoverySpec) *bool { return d.HTTPRoutes }) {
		return "discovery.httpRoutes is enabled but the Gateway API CRDs were absent when the operator started, " +
			"so the discovered set is incomplete"
	}
	if !r.GatewaysAvailable && explicitlyEnabled(discovery, func(d *v1alpha1.DiscoverySpec) *bool { return d.Gateways }) {
		return "discovery.gateways is enabled but the Gateway API CRDs were absent when the operator started, " +
			"so the discovered set is incomplete"
	}
	return ""
}

func (r *WildcardCertificatePolicyReconciler) recordPlan(
	policy *v1alpha1.WildcardCertificatePolicy, state app.DesiredState,
) {
	now := metav1.NewTime(r.Clock.Now())
	policy.Status.ObservedGeneration = policy.Generation
	policy.Status.DiscoveredHosts = int32(len(state.DiscoveredHosts))
	policy.Status.SkippedHostCount = int32(len(state.Skipped))
	policy.Status.LastDiscoveryTime = &now

	policy.Status.RequiredCertificateCount = int32(len(state.Certificates))
	policy.Status.RequiredCertificates = make([]v1alpha1.PlannedCertificate, 0, len(state.Certificates))
	listenerCount := 0
	listeners := make([]v1alpha1.ListenerGuidance, 0, len(state.Certificates))
	for _, cert := range state.Certificates {
		policy.Status.RequiredCertificates = append(policy.Status.RequiredCertificates, v1alpha1.PlannedCertificate{
			Name:             cert.Name,
			Zone:             cert.Zone,
			DNSNames:         truncate(cert.DNSNames, maxReportedDNSNames),
			SecretName:       cert.SecretName,
			SecretIdentifier: cert.SecretIdentifier,
		})
		for _, group := range cert.Listeners {
			listenerCount++
			if len(listeners) >= maxReportedListeners {
				continue
			}
			listeners = append(listeners, v1alpha1.ListenerGuidance{
				Hostnames:        group,
				KeyVaultSecretID: cert.SecretIdentifier,
			})
		}
	}

	// Emitted as data for Terraform or the CLI to apply. The operator holds no
	// ARM permissions and never writes gateway configuration itself.
	policy.Status.ApplicationGateway = &v1alpha1.ApplicationGatewayGuidance{
		Listeners:     listeners,
		ListenerCount: int32(listenerCount),
	}

	skipped := truncate(state.Skipped, maxReportedSkippedHosts)
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
	return updateStatus(ctx, r.Client, policy)
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

// pinnedVaultNames drops the API's name type, which the planner and the domain
// deliberately know nothing about.
func pinnedVaultNames(pinned map[string]v1alpha1.VaultObjectName) map[string]string {
	if len(pinned) == 0 {
		return nil
	}
	out := make(map[string]string, len(pinned))
	for zone, name := range pinned {
		out[zone] = string(name)
	}
	return out
}

func namespaceSelector(discovery *v1alpha1.DiscoverySpec) *metav1.LabelSelector {
	if discovery == nil {
		return nil
	}
	return discovery.NamespaceSelector
}

// explicitlyEnabled reports whether the field was actually set to true, as
// opposed to merely defaulting to it.
//
// The distinction matters only where the absence of a source should be treated
// as a problem. "httpRoutes: true" written by hand states a requirement; the
// same value arrived at by default states nothing, because it is what every
// policy carries whether or not the cluster runs Gateway API. Using enabled()
// here would withhold pruning on every cluster without Gateway API installed,
// which is most of them.
func explicitlyEnabled(discovery *v1alpha1.DiscoverySpec, pick func(*v1alpha1.DiscoverySpec) *bool) bool {
	if discovery == nil {
		return false
	}
	value := pick(discovery)
	return value != nil && *value
}

// enabled defaults an optional boolean to true, matching the CRD defaults.
func enabled(discovery *v1alpha1.DiscoverySpec, pick func(*v1alpha1.DiscoverySpec) *bool) bool {
	if discovery == nil {
		return true
	}
	value := pick(discovery)
	return value == nil || *value
}

// truncate bounds a status list to what the CRD accepts, without copying.
func truncate[T any](items []T, max int) []T {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func orphanVerb(policy v1alpha1.OrphanPolicy) string {
	if policy == v1alpha1.OrphanPrune {
		return "pruned"
	}
	return "retained (the Key Vault certificate is never deleted)"
}
