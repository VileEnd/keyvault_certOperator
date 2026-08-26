package controller

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/azure"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/pkcs12"
)

// SecretRefIndexKey indexes sync resources by the Secret they reference, so a
// Secret event can be mapped back to the resources that care about it.
const SecretRefIndexKey = ".spec.source.secretRef.name"

// DefaultResyncInterval is used when a resource does not set one. It is
// deliberately on the order of an hour: it exists to catch drift applied to Key
// Vault out of band, while ordinary renewals arrive as Secret watch events
// within seconds.
const DefaultResyncInterval = time.Hour

// KeyVaultCertificateSyncReconciler keeps one TLS Secret mirrored into one Key
// Vault certificate.
type KeyVaultCertificateSyncReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	Source app.CertificateSource
	Vault  app.VaultRepository
	Clock  app.Clock
}

// +kubebuilder:rbac:groups=certsync.vileend.io,resources=keyvaultcertificatesyncs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certsync.vileend.io,resources=keyvaultcertificatesyncs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certsync.vileend.io,resources=keyvaultcertificatesyncs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile brings one certificate into Key Vault.
func (r *KeyVaultCertificateSyncReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var sync v1alpha1.KeyVaultCertificateSync
	if err := r.Get(ctx, req.NamespacedName, &sync); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !sync.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &sync)
	}

	if controllerutil.AddFinalizer(&sync, v1alpha1.FinalizerName) {
		if err := r.Update(ctx, &sync); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
	}

	resync := resyncInterval(sync.Spec.SyncPolicy)

	outcome, err := r.sync(ctx, &sync)
	if err != nil {
		reason, retryable := classify(err)
		if reason == ReasonSourceNotFound {
			log.V(1).Info("waiting for the source certificate", "reason", err.Error())
		} else {
			log.Error(err, "sync failed", "reason", reason, "retryable", retryable)
			syncTotal.WithLabelValues(sync.Namespace, sync.Name, "error").Inc()
		}

		setFalse(&sync.Status.Conditions, v1alpha1.ConditionSynced, reason, err.Error(), sync.Generation)
		setFalse(&sync.Status.Conditions, v1alpha1.ConditionReady, reason, err.Error(), sync.Generation)
		r.event(&sync, corev1.EventTypeWarning, reason, "Sync", err.Error())

		if statusErr := r.updateStatus(ctx, &sync); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		if retryable {
			return ctrl.Result{}, err
		}
		// Not retryable by backoff, but still worth re-checking: the fix usually
		// arrives as a renewed Secret, which also wakes this controller directly.
		return ctrl.Result{RequeueAfter: jitter(resync)}, nil
	}

	r.applyOutcome(&sync, outcome)
	if err := r.updateStatus(ctx, &sync); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: jitter(resync)}, nil
}

func (r *KeyVaultCertificateSyncReconciler) sync(
	ctx context.Context, sync *v1alpha1.KeyVaultCertificateSync,
) (app.SyncOutcome, error) {
	vaultURL, err := azure.VaultURL(vaultTarget(sync.Spec.KeyVault), azure.Cloud(sync.Spec.KeyVault.Cloud))
	if err != nil {
		return app.SyncOutcome{}, fmt.Errorf("%w: %w", domain.ErrInvalidVaultName, err)
	}

	encoder, err := pkcs12.NewEncoder(pkcs12Profile(sync.Spec.SyncPolicy))
	if err != nil {
		return app.SyncOutcome{}, fmt.Errorf("%w: %w", domain.ErrInvalidVaultName, err)
	}

	syncer := &app.Syncer{Source: r.Source, Vault: r.Vault, Encode: encoder, Clock: r.Clock}
	return syncer.Sync(ctx, app.SyncRequest{
		// Cross-namespace references are not offered, so the Secret is always in
		// the resource's own namespace.
		Source: app.SecretRef{Namespace: sync.Namespace, Name: sync.Spec.Source.SecretRef.Name},
		Vault: app.VaultRef{
			VaultURL:        vaultURL,
			CertificateName: sync.Spec.KeyVault.CertificateName,
		},
	})
}

func (r *KeyVaultCertificateSyncReconciler) applyOutcome(
	sync *v1alpha1.KeyVaultCertificateSync, outcome app.SyncOutcome,
) {
	now := metav1.NewTime(r.Clock.Now())
	notAfter := metav1.NewTime(outcome.NotAfter)

	sync.Status.ObservedGeneration = sync.Generation
	sync.Status.CertificateName = outcome.CertificateName
	sync.Status.SecretIdentifier = outcome.SecretIdentifier
	sync.Status.LastSyncedThumbprint = outcome.Thumbprint
	sync.Status.ChainDigest = outcome.ChainDigest
	sync.Status.DNSNames = outcome.DNSNames
	sync.Status.NotAfter = &notAfter
	sync.Status.LastSyncTime = &now
	if outcome.Version != "" {
		sync.Status.VaultCertificateVersion = outcome.Version
	}

	reason, message := ReasonUpToDate, "certificate in Key Vault already matches the cluster"
	if outcome.Action == domain.ActionImport {
		reason = ReasonImported
		message = fmt.Sprintf("imported into Key Vault (%s)", outcome.Reason)
		r.event(sync, corev1.EventTypeNormal, ReasonImported, "Import", message)
	}
	if outcome.Warning != "" {
		r.event(sync, corev1.EventTypeWarning, "ExpiryRegression", "Import", outcome.Warning)
	}

	setTrue(&sync.Status.Conditions, v1alpha1.ConditionSynced, reason, message, sync.Generation)
	setTrue(&sync.Status.Conditions, v1alpha1.ConditionReady, ReasonSynced,
		"certificate is available at "+outcome.SecretIdentifier, sync.Generation)

	syncTotal.WithLabelValues(sync.Namespace, sync.Name, string(outcome.Action)).Inc()
	lastSuccessTimestamp.WithLabelValues(sync.Namespace, sync.Name).Set(float64(r.Clock.Now().Unix()))
	certificateNotAfter.
		WithLabelValues(sync.Namespace, sync.Name, outcome.CertificateName).
		Set(float64(outcome.NotAfter.Unix()))
}

// finalize releases the resource without touching Azure.
//
// The Key Vault certificate is deliberately left in place. Application Gateway
// may still be serving it, and deleting or disabling the version a listener
// holds takes that listener down. Cleaning up the vault is an operator decision,
// not something a "kubectl delete" should trigger.
func (r *KeyVaultCertificateSyncReconciler) finalize(
	ctx context.Context, sync *v1alpha1.KeyVaultCertificateSync,
) (ctrl.Result, error) {
	if controllerutil.RemoveFinalizer(sync, v1alpha1.FinalizerName) {
		if err := r.Update(ctx, sync); err != nil {
			return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
		}
	}
	certificateNotAfter.DeleteLabelValues(sync.Namespace, sync.Name, sync.Status.CertificateName)
	lastSuccessTimestamp.DeleteLabelValues(sync.Namespace, sync.Name)
	return ctrl.Result{}, nil
}

// updateStatus writes status, tolerating a conflict by letting the next
// reconcile recompute it rather than retrying a stale object.
func (r *KeyVaultCertificateSyncReconciler) updateStatus(
	ctx context.Context, sync *v1alpha1.KeyVaultCertificateSync,
) error {
	if err := r.Status().Update(ctx, sync); err != nil {
		if apierrors.IsConflict(err) {
			return nil
		}
		return fmt.Errorf("updating status: %w", err)
	}
	return nil
}

func (r *KeyVaultCertificateSyncReconciler) event(obj *v1alpha1.KeyVaultCertificateSync,
	eventType, reason, action, note string,
) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(obj, nil, eventType, reason, action, "%s", note)
}

// SetupWithManager registers the controller and the index that makes Secret
// events routable.
func (r *KeyVaultCertificateSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(), &v1alpha1.KeyVaultCertificateSync{}, SecretRefIndexKey,
		func(obj client.Object) []string {
			sync, ok := obj.(*v1alpha1.KeyVaultCertificateSync)
			if !ok || sync.Spec.Source.SecretRef.Name == "" {
				return nil
			}
			return []string{sync.Spec.Source.SecretRef.Name}
		},
	); err != nil {
		return fmt.Errorf("indexing %s: %w", SecretRefIndexKey, err)
	}

	managed, err := predicate.LabelSelectorPredicate(metav1.LabelSelector{
		MatchLabels: map[string]string{v1alpha1.LabelManaged: v1alpha1.LabelManagedValue},
	})
	if err != nil {
		return fmt.Errorf("building the managed-secret predicate: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KeyVaultCertificateSync{}).
		Named("keyvaultcertificatesync").
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.syncsForSecret),
			// Secrets carry no generation, so a data change is only visible as a
			// resourceVersion change. The real comparison happens against Key
			// Vault's thumbprint, which is why a spurious wake is harmless.
			builder.WithPredicates(predicate.And(managed, predicate.ResourceVersionChangedPredicate{})),
		).
		Complete(r)
}

// syncsForSecret maps a Secret event to the resources referencing it, so a
// renewal propagates within seconds instead of waiting for the resync.
func (r *KeyVaultCertificateSyncReconciler) syncsForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	var list v1alpha1.KeyVaultCertificateSyncList
	if err := r.List(ctx, &list,
		client.InNamespace(obj.GetNamespace()),
		client.MatchingFields{SecretRefIndexKey: obj.GetName()},
	); err != nil {
		logf.FromContext(ctx).Error(err, "mapping secret to sync resources",
			"secret", client.ObjectKeyFromObject(obj))
		return nil
	}

	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&list.Items[i]),
		})
	}
	return requests
}

// ManagedSecretSelector is the label selector the manager's cache uses to limit
// which Secrets are ever read into memory.
func ManagedSecretSelector() labels.Selector {
	return labels.SelectorFromSet(labels.Set{v1alpha1.LabelManaged: v1alpha1.LabelManagedValue})
}

func vaultTarget(spec v1alpha1.KeyVaultSpec) string {
	if spec.VaultURL != "" {
		return spec.VaultURL
	}
	return spec.Name
}

func resyncInterval(policy *v1alpha1.SyncPolicySpec) time.Duration {
	if policy == nil || policy.ResyncInterval == nil || policy.ResyncInterval.Duration <= 0 {
		return DefaultResyncInterval
	}
	return policy.ResyncInterval.Duration
}

func pkcs12Profile(policy *v1alpha1.SyncPolicySpec) pkcs12.Profile {
	if policy == nil {
		return pkcs12.ProfileLegacy
	}
	return pkcs12.Profile(policy.PKCS12Profile)
}

// jitter spreads requeues so that many resources do not all wake together and
// hit Key Vault's import throttle in one burst.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultResyncInterval
	}
	spread := d / 10
	if spread <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(int64(spread)))
}
