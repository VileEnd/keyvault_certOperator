package app

import (
	"context"
	"fmt"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

// PolicySpec is the discovery configuration, mirroring the CRD spec but free of
// Kubernetes types.
type PolicySpec struct {
	// Zones is the required allowlist of DNS zones issuance may happen inside.
	Zones []string
	// MaxCertificates caps the plan; zero means unlimited.
	MaxCertificates int
	// Grouping selects how SANs are packed into certificates.
	Grouping domain.Grouping
	// IssueZoneWildcards plans "*.zone" for every zone regardless of discovery.
	IssueZoneWildcards bool
	// VaultURL is the Key Vault the resulting certificates are synced to.
	VaultURL string
}

// DesiredCertificate is one certificate the cluster should have, together with
// everything the controller needs to create it and everything an operator needs
// to wire up an Application Gateway listener.
type DesiredCertificate struct {
	domain.CertificateRequest

	// SecretName is the Kubernetes Secret cert-manager will write.
	SecretName string
	// SecretIdentifier is the versionless Key Vault URI for the listener.
	SecretIdentifier string
	// Listeners groups the SANs into Application Gateway listener-sized sets.
	//
	// A certificate may carry more SANs than one listener can serve: Application
	// Gateway allows at most five host names per multi-site listener, while a
	// certificate has no such limit. Pre-splitting them here means the status
	// shows a configuration that can actually be applied.
	Listeners [][]string
}

// DesiredState is the full result of a discovery pass.
type DesiredState struct {
	Certificates    []DesiredCertificate
	Skipped         []domain.SkippedHost
	DiscoveredHosts []string
}

// Planner turns the hostnames routed by the cluster into the certificates that
// must exist. It is the only place discovery logic lives.
type Planner struct {
	Hosts HostSource
}

// NewPlanner wires a Planner.
func NewPlanner(hosts HostSource) *Planner { return &Planner{Hosts: hosts} }

// Plan discovers hostnames and derives the desired certificate set.
//
// The guards live in domain.BuildPlan: a required zone allowlist, a Public
// Suffix List check, and a certificate cap. They exist because discovery-driven
// ACME issuance is the one part of this operator that a third party can trigger
// -- anyone able to create an Ingress would otherwise be able to spend the
// cluster's Let's Encrypt rate limit for a registered domain.
func (p *Planner) Plan(ctx context.Context, spec PolicySpec) (DesiredState, error) {
	hosts, err := p.Hosts.Hosts(ctx)
	if err != nil {
		return DesiredState{}, fmt.Errorf("discovering hostnames: %w", err)
	}

	plan, err := domain.BuildPlan(domain.PlanInput{
		Hosts:              hosts,
		Zones:              spec.Zones,
		MaxCertificates:    spec.MaxCertificates,
		Grouping:           spec.Grouping,
		IssueZoneWildcards: spec.IssueZoneWildcards,
	})
	if err != nil {
		return DesiredState{}, err
	}

	state := DesiredState{
		Skipped:         plan.Skipped,
		DiscoveredHosts: hosts,
		Certificates:    make([]DesiredCertificate, 0, len(plan.Certificates)),
	}
	for _, cert := range plan.Certificates {
		ref := VaultRef{VaultURL: spec.VaultURL, CertificateName: cert.Name}
		state.Certificates = append(state.Certificates, DesiredCertificate{
			CertificateRequest: cert,
			SecretName:         cert.Name + "-tls",
			SecretIdentifier:   ref.SecretIdentifier(),
			Listeners:          domain.SplitListenerHostnames(cert.DNSNames),
		})
	}
	return state, nil
}
