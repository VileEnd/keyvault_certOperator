package domain

import (
	"bytes"
	"fmt"
	"time"
)

// Action is what the sync should do with a certificate.
type Action string

const (
	// ActionNone means Key Vault already holds this exact certificate.
	ActionNone Action = "None"
	// ActionImport means the certificate must be imported.
	ActionImport Action = "Import"
)

// Decision reasons, stable enough to assert on in tests and surface in status.
const (
	ReasonAbsentInVault = "AbsentInVault"
	ReasonLeafChanged   = "LeafChanged"
	ReasonChainChanged  = "ChainChanged"
	ReasonUpToDate      = "UpToDate"
)

// VaultSnapshot is the cheap view of what Key Vault currently holds, obtained
// with a single GetCertificate. ChainDigest comes from the tag we stamp on
// import; reading the stored chain itself would require secrets/getSecret.
type VaultSnapshot struct {
	Exists      bool
	Thumbprint  []byte
	ChainDigest string
	Enabled     bool
	NotAfter    time.Time
}

// Decision is the outcome of comparing desired state against Key Vault.
type Decision struct {
	Action Action
	Reason string
	// Warning is set for situations worth surfacing but not worth blocking on.
	Warning string
}

// Decide reports whether the desired bundle must be imported into Key Vault.
//
// This check is mandatory rather than an optimisation. ImportCertificate is not
// idempotent: every call mints a new, permanent version. Versions cannot be
// deleted, more than 500 of them breaks the vault's backup operation, the import
// throttle is 300 per 10 seconds, and each new version is a candidate for an
// Application Gateway certificate rotation within four hours. Re-importing an
// unchanged certificate is therefore actively harmful, not merely wasteful.
func Decide(desired *Bundle, snap VaultSnapshot, now time.Time) (Decision, error) {
	if desired == nil {
		return Decision{}, ErrNoCertificates
	}
	if err := desired.Validate(now); err != nil {
		return Decision{}, err
	}

	if !snap.Exists {
		return Decision{Action: ActionImport, Reason: ReasonAbsentInVault}, nil
	}

	var warning string
	// A regression in expiry means the cluster now holds an older certificate
	// than Key Vault. The cluster is the source of truth so we still import,
	// but this is nearly always a mistake and deserves to be visible.
	if !snap.NotAfter.IsZero() && desired.NotAfter().Before(snap.NotAfter) {
		warning = fmt.Sprintf(
			"source certificate expires %s, earlier than the one already in Key Vault (%s)",
			desired.NotAfter().Format(time.RFC3339), snap.NotAfter.Format(time.RFC3339))
	}

	if !bytes.Equal(snap.Thumbprint, desired.Thumbprint()) {
		return Decision{Action: ActionImport, Reason: ReasonLeafChanged, Warning: warning}, nil
	}

	// The leaf can be byte-identical while the issuing chain has moved on, which
	// is exactly what happens when the CA rotates intermediates. Key Vault's
	// X509Thumbprint covers the leaf only, so the chain is compared separately.
	if snap.ChainDigest != desired.ChainDigest() {
		return Decision{Action: ActionImport, Reason: ReasonChainChanged, Warning: warning}, nil
	}

	return Decision{Action: ActionNone, Reason: ReasonUpToDate, Warning: warning}, nil
}
