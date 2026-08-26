package app

import (
	"context"
	"fmt"
	"time"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

// SyncRequest is one certificate to reconcile into Key Vault.
type SyncRequest struct {
	Source SecretRef
	Vault  VaultRef
}

// SyncOutcome describes what happened, in the terms the CRD status reports.
type SyncOutcome struct {
	// Action is whether an import actually took place.
	Action domain.Action
	// Reason explains the action; see the domain.Reason* constants.
	Reason string
	// Warning is non-empty when something deserves attention but not failure.
	Warning string

	Thumbprint  string
	ChainDigest string
	NotAfter    time.Time
	DNSNames    []string

	// Version is set only when a new Key Vault version was created.
	Version string
	// SecretIdentifier is the versionless URI for the Application Gateway listener.
	SecretIdentifier string
}

// Syncer reconciles one Kubernetes Secret into one Key Vault certificate.
//
// This is the only place the sync workflow exists. Both the controller that
// users drive directly and the one that generates certificates from discovery
// funnel through here, so the ordering guarantees below hold for every path.
type Syncer struct {
	Source CertificateSource
	Vault  VaultRepository
	Encode Encoder
	Clock  Clock
}

// NewSyncer wires a Syncer, defaulting the clock.
func NewSyncer(source CertificateSource, vault VaultRepository, encoder Encoder) *Syncer {
	return &Syncer{Source: source, Vault: vault, Encode: encoder, Clock: RealClock{}}
}

// Sync brings one certificate into Key Vault, importing only when it differs.
//
// The snapshot-then-decide step before any import is load-bearing rather than an
// optimisation. ImportCertificate is not idempotent: each call mints a permanent
// version, versions can never be deleted, more than 500 breaks the vault's
// backup operation, and every new version is a candidate for an Application
// Gateway certificate rotation within four hours. A reconcile loop that imported
// unconditionally would therefore degrade the vault and churn TLS on every pass.
func (s *Syncer) Sync(ctx context.Context, req SyncRequest) (SyncOutcome, error) {
	if err := domain.ValidateVaultCertificateName(req.Vault.CertificateName); err != nil {
		return SyncOutcome{}, err
	}

	bundle, err := s.Source.Load(ctx, req.Source)
	if err != nil {
		return SyncOutcome{}, fmt.Errorf("loading certificate from %s: %w", req.Source, err)
	}

	snapshot, err := s.Vault.Snapshot(ctx, req.Vault)
	if err != nil {
		return SyncOutcome{}, fmt.Errorf("reading %s from Key Vault: %w", req.Vault.CertificateName, err)
	}

	decision, err := domain.Decide(bundle, snapshot, s.Clock.Now())
	if err != nil {
		return SyncOutcome{}, err
	}

	outcome := SyncOutcome{
		Action:           decision.Action,
		Reason:           decision.Reason,
		Warning:          decision.Warning,
		Thumbprint:       bundle.ThumbprintHex(),
		ChainDigest:      bundle.ChainDigest(),
		NotAfter:         bundle.NotAfter(),
		DNSNames:         bundle.DNSNames(),
		SecretIdentifier: req.Vault.SecretIdentifier(),
	}

	if decision.Action == domain.ActionNone {
		return outcome, nil
	}

	blob, password, err := s.Encode.Encode(bundle)
	if err != nil {
		return SyncOutcome{}, fmt.Errorf("encoding certificate: %w", err)
	}

	result, err := s.Vault.Import(ctx, req.Vault, ImportRequest{
		Blob:        blob,
		Password:    password,
		ContentType: s.Encode.ContentType(),
		Tags:        tagsFor(req, bundle),
	})
	if err != nil {
		return SyncOutcome{}, fmt.Errorf("importing %s into Key Vault: %w", req.Vault.CertificateName, err)
	}

	outcome.Version = result.Version
	return outcome, nil
}

func tagsFor(req SyncRequest, bundle *domain.Bundle) map[string]string {
	return map[string]string{
		TagManagedBy:       TagManagedByValue,
		TagSourceNamespace: req.Source.Namespace,
		TagSourceSecret:    req.Source.Name,
		TagChainDigest:     bundle.ChainDigest(),
		TagNotAfter:        bundle.NotAfter().UTC().Format(time.RFC3339),
		TagSerial:          bundle.SerialHex(),
	}
}
