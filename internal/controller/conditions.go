package controller

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

// Condition reasons. Kubernetes requires these to be single CamelCase tokens.
const (
	ReasonSynced             = "Synced"
	ReasonUpToDate           = "UpToDate"
	ReasonImported           = "Imported"
	ReasonSourceInvalid      = "SourceInvalid"
	ReasonSourceNotFound     = "SourceNotFound"
	ReasonCertificateExpired = "CertificateExpired"
	ReasonConfigInvalid      = "ConfigInvalid"
	ReasonVaultError         = "VaultError"
	ReasonDiscoveryFailed    = "DiscoveryFailed"
	// ReasonVaultAccessDenied means Key Vault answered 401 or 403. It is kept
	// apart from VaultError because it is the one vault failure retrying does
	// not resolve: somebody has to grant a permission, or finish propagating
	// the grant they just made.
	ReasonVaultAccessDenied = "VaultAccessDenied"
	// ReasonEncodingFailed means the PKCS#12 payload could not be built. Nothing
	// was sent to Azure, so this failure says nothing at all about the vault.
	ReasonEncodingFailed = "EncodingFailed"
	// ReasonSourceSecretNotVisible means the Secret exists but is not labelled,
	// so it is outside the cache this operator watches. Reporting SourceNotFound
	// for it would deny an object that kubectl plainly shows.
	ReasonSourceSecretNotVisible = "SourceSecretNotVisible"
	ReasonIssuanceFailed         = "IssuanceFailed"
	ReasonCertManagerMissing     = "CertManagerMissing"
	ReasonCertManagerFound       = "CertManagerFound"
	// ReasonPruneWithheld means orphaned resources were found but deliberately
	// not deleted, because the discovery pass they were judged against could
	// not be trusted to be complete.
	ReasonPruneWithheld = "PruneWithheld"
	// ReasonVaultObjectConflict means a sync resource this policy generated
	// earlier still writes a Key Vault object the current plan writes under
	// another name. Applying that plan would put two writers on one object, so
	// it is refused whole.
	ReasonVaultObjectConflict = "VaultObjectConflict"
)

// updateStatus writes a resource's status subresource, tolerating the two
// failures that mean "this write no longer matters".
//
// A conflict means someone else changed the object, so the next reconcile
// recomputes status from the current one -- retrying against a stale object
// would only overwrite fresher data. A NotFound means the resource was deleted
// while this pass was running.
//
// Shared by both controllers on purpose. They previously had one of these each,
// tolerating a different one of the two errors, so which transient failure
// turned into a requeue depended on which controller you were in.
func updateStatus(ctx context.Context, c client.Client, obj client.Object) error {
	if err := c.Status().Update(ctx, obj); err != nil {
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("updating status: %w", err)
	}
	return nil
}

func setCondition(conditions *[]metav1.Condition, conditionType, reason, message string,
	status metav1.ConditionStatus, generation int64,
) {
	// SetStatusCondition only moves LastTransitionTime when the status actually
	// changes, so calling this every reconcile stays idempotent.
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	})
}

func setTrue(conditions *[]metav1.Condition, conditionType, reason, message string, generation int64) {
	setCondition(conditions, conditionType, reason, message, metav1.ConditionTrue, generation)
}

func setFalse(conditions *[]metav1.Condition, conditionType, reason, message string, generation int64) {
	setCondition(conditions, conditionType, reason, message, metav1.ConditionFalse, generation)
}

// classify decides whether an error can be fixed by retrying.
//
// Domain errors describe the data, not a transient failure: an expired
// certificate or a key that does not match its certificate will not repair
// itself on the next attempt. Retrying those with exponential backoff would
// spin the queue and bury the real signal, so they are reported as a condition
// and re-checked on the ordinary resync instead. Everything else -- Key Vault
// throttling, API server hiccups, network failures -- is worth a backoff.
func classify(err error) (reason string, retryable bool) {
	switch {
	case apierrors.IsNotFound(err):
		// Normal while cert-manager is still issuing: the sync resource is
		// created alongside the Certificate, so it necessarily runs before the
		// Secret exists. The Secret watch wakes this controller the moment it
		// appears, so there is nothing to back off for.
		return ReasonSourceNotFound, false
	case errors.Is(err, domain.ErrExpired), errors.Is(err, domain.ErrNotYetValid):
		return ReasonCertificateExpired, false
	case errors.Is(err, domain.ErrSourceSecretNotVisible):
		// Deliberately not SourceNotFound: the Secret is in the cluster, and
		// being told it was not found sends people to cert-manager instead of to
		// the label that is missing. Adding the label moves the Secret into the
		// watch, which wakes this controller, so there is nothing to back off for.
		return ReasonSourceSecretNotVisible, false
	case errors.Is(err, domain.ErrNoCertificates),
		errors.Is(err, domain.ErrNoPrivateKey),
		errors.Is(err, domain.ErrKeyMismatch),
		errors.Is(err, domain.ErrUnsupportedKey),
		errors.Is(err, domain.ErrNoDNSNames),
		// Shape rather than content -- wrong type, no tls.crt, no tls.key -- but
		// the same subsystem and the same fix: the Secret is what has to change.
		errors.Is(err, domain.ErrInvalidSourceSecret):
		return ReasonSourceInvalid, false
	case errors.Is(err, domain.ErrInvalidVaultName),
		errors.Is(err, domain.ErrInvalidPKCS12Profile),
		errors.Is(err, domain.ErrInvalidZone),
		errors.Is(err, domain.ErrInvalidHost),
		// Terminal on purpose: no amount of retrying makes a vault permitted,
		// and stopping here names the allowlist rather than the access denial
		// the vault would otherwise answer with.
		errors.Is(err, domain.ErrVaultNotAllowed):
		return ReasonConfigInvalid, false
	case errors.Is(err, domain.ErrPKCS12Encoding):
		// Deterministic in the bundle and the profile, and it happens before the
		// first byte reaches Azure, so a backoff would only re-run the same
		// encode against the same input.
		return ReasonEncodingFailed, false
	case errors.Is(err, domain.ErrVaultAccessDenied):
		// The one 4xx worth separating from the retryable rest: no backoff makes
		// a grant appear, and backing off against one forever is exactly how a
		// misconfigured vault came to look like throttling. Not permanent,
		// though -- a grant made seconds ago answers the same 403 until it
		// propagates -- so the sync controller re-checks it on
		// AccessDeniedRetryInterval rather than waiting out the whole resync.
		return ReasonVaultAccessDenied, false
	default:
		return ReasonVaultError, true
	}
}
