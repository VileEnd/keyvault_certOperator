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
	ReasonIssuanceFailed     = "IssuanceFailed"
	ReasonCertManagerMissing = "CertManagerMissing"
	ReasonCertManagerFound   = "CertManagerFound"
	// ReasonPruneWithheld means orphaned resources were found but deliberately
	// not deleted, because the discovery pass they were judged against could
	// not be trusted to be complete.
	ReasonPruneWithheld = "PruneWithheld"
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
	case errors.Is(err, domain.ErrNoCertificates),
		errors.Is(err, domain.ErrNoPrivateKey),
		errors.Is(err, domain.ErrKeyMismatch),
		errors.Is(err, domain.ErrUnsupportedKey),
		errors.Is(err, domain.ErrNoDNSNames):
		return ReasonSourceInvalid, false
	case errors.Is(err, domain.ErrInvalidVaultName),
		errors.Is(err, domain.ErrInvalidPKCS12Profile),
		errors.Is(err, domain.ErrInvalidZone),
		errors.Is(err, domain.ErrInvalidHost),
		// Terminal on purpose: no amount of retrying makes a vault permitted,
		// and the 403 it would otherwise produce looks retryable.
		errors.Is(err, domain.ErrVaultNotAllowed):
		return ReasonConfigInvalid, false
	default:
		return ReasonVaultError, true
	}
}
