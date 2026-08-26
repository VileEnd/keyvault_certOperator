package controller

import (
	"errors"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

// Condition reasons. Kubernetes requires these to be single CamelCase tokens.
const (
	ReasonSynced             = "Synced"
	ReasonUpToDate           = "UpToDate"
	ReasonImported           = "Imported"
	ReasonSourceInvalid      = "SourceInvalid"
	ReasonCertificateExpired = "CertificateExpired"
	ReasonConfigInvalid      = "ConfigInvalid"
	ReasonVaultError         = "VaultError"
	ReasonDiscoveryFailed    = "DiscoveryFailed"
	ReasonIssuanceFailed     = "IssuanceFailed"
	ReasonCertManagerMissing = "CertManagerMissing"
	ReasonCertManagerFound   = "CertManagerFound"
)

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
	case errors.Is(err, domain.ErrExpired), errors.Is(err, domain.ErrNotYetValid):
		return ReasonCertificateExpired, false
	case errors.Is(err, domain.ErrNoCertificates),
		errors.Is(err, domain.ErrNoPrivateKey),
		errors.Is(err, domain.ErrKeyMismatch),
		errors.Is(err, domain.ErrUnsupportedKey),
		errors.Is(err, domain.ErrNoDNSNames):
		return ReasonSourceInvalid, false
	case errors.Is(err, domain.ErrInvalidVaultName),
		errors.Is(err, domain.ErrInvalidZone),
		errors.Is(err, domain.ErrInvalidHost):
		return ReasonConfigInvalid, false
	default:
		return ReasonVaultError, true
	}
}
