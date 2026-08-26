package app_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

type fakeHosts struct {
	hosts []string
	err   error
}

func (f *fakeHosts) Hosts(context.Context) ([]string, error) { return f.hosts, f.err }

func TestPlanBuildsCertificatesAndListenerConfiguration(t *testing.T) {
	t.Parallel()
	planner := app.NewPlanner(&fakeHosts{hosts: []string{
		"api.x.com", "web.x.com", "x.com", "a.sub.x.com", "nope.evil.com",
	}})

	state, err := planner.Plan(t.Context(), app.PolicySpec{
		Zones:    []string{"x.com"},
		VaultURL: "https://my-vault.vault.azure.net",
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if len(state.Certificates) != 1 {
		t.Fatalf("certificates = %d, want 1", len(state.Certificates))
	}
	cert := state.Certificates[0]

	// Many hostnames collapse onto a single SAN certificate per zone, which is
	// what keeps the Application Gateway listener and certificate counts far
	// below the hard limit of 100.
	wantNames := []string{"*.sub.x.com", "*.x.com", "x.com"}
	if !reflect.DeepEqual(cert.DNSNames, wantNames) {
		t.Errorf("SANs = %v, want %v", cert.DNSNames, wantNames)
	}
	if cert.Name != "wildcard-x-com" {
		t.Errorf("name = %q, want wildcard-x-com", cert.Name)
	}
	if cert.SecretName != "wildcard-x-com-tls" {
		t.Errorf("secret name = %q", cert.SecretName)
	}
	if cert.SecretIdentifier != "https://my-vault.vault.azure.net/secrets/wildcard-x-com" {
		t.Errorf("secret identifier = %q", cert.SecretIdentifier)
	}

	// Three SANs fit inside a single listener's five-host-name budget.
	if len(cert.Listeners) != 1 || !reflect.DeepEqual(cert.Listeners[0], wantNames) {
		t.Errorf("listeners = %v, want one group of %v", cert.Listeners, wantNames)
	}

	// Hosts outside the allowlist are reported, never silently dropped.
	if len(state.Skipped) != 1 || state.Skipped[0].Host != "nope.evil.com" {
		t.Errorf("skipped = %+v, want nope.evil.com", state.Skipped)
	}
}

func TestPlanSplitsLargeCertificatesAcrossListeners(t *testing.T) {
	t.Parallel()
	// Application Gateway allows five host names per listener; a certificate has
	// no such limit, so the SANs have to be spread across several listeners.
	planner := app.NewPlanner(&fakeHosts{hosts: []string{
		"a.one.com", "a.two.com", "a.three.com", "a.four.com", "a.five.com", "a.six.com",
	}})

	state, err := planner.Plan(t.Context(), app.PolicySpec{
		Zones:    []string{"one.com", "two.com", "three.com", "four.com", "five.com", "six.com"},
		Grouping: domain.GroupingPerWildcard,
		VaultURL: "https://my-vault.vault.azure.net",
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(state.Certificates) != 6 {
		t.Fatalf("certificates = %d, want 6", len(state.Certificates))
	}
	for _, cert := range state.Certificates {
		for _, group := range cert.Listeners {
			if len(group) > domain.MaxListenerHostnames {
				t.Errorf("listener group %v exceeds the cap of %d", group, domain.MaxListenerHostnames)
			}
		}
	}
}

func TestPlanRequiresAZoneAllowlist(t *testing.T) {
	t.Parallel()
	// Without zones there is no boundary on ACME issuance, so this must fail
	// loudly rather than default to allowing everything.
	planner := app.NewPlanner(&fakeHosts{hosts: []string{"a.x.com"}})

	_, err := planner.Plan(t.Context(), app.PolicySpec{VaultURL: "https://my-vault.vault.azure.net"})
	if !errors.Is(err, domain.ErrInvalidZone) {
		t.Errorf("Plan() = %v, want ErrInvalidZone", err)
	}
}

func TestPlanPropagatesDiscoveryErrors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("list ingresses: forbidden")
	planner := app.NewPlanner(&fakeHosts{err: sentinel})

	_, err := planner.Plan(t.Context(), app.PolicySpec{Zones: []string{"x.com"}})
	if !errors.Is(err, sentinel) {
		t.Errorf("Plan() = %v, want it to wrap %v", err, sentinel)
	}
}
