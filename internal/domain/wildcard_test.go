package domain_test

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

func TestBuildPlanDerivesCoveringWildcards(t *testing.T) {
	t.Parallel()
	// A wildcard matches exactly one label: "*.x.com" covers "a.x.com" but
	// neither "x.com" nor "a.b.x.com". The apex needs its own SAN and a deeper
	// host needs a wildcard for its immediate parent.
	tests := []struct {
		name  string
		hosts []string
		zones []string
		want  []domain.CertificateRequest
	}{
		{
			name:  "host yields a parent wildcard",
			hosts: []string{"api.x.com"},
			zones: []string{"x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com"}},
			},
		},
		{
			name:  "apex is added as its own SAN",
			hosts: []string{"api.x.com", "x.com"},
			zones: []string{"x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com", "x.com"}},
			},
		},
		{
			name:  "deeper host yields a deeper wildcard on the same zone cert",
			hosts: []string{"api.x.com", "a.sub.x.com"},
			zones: []string{"x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.sub.x.com", "*.x.com"}},
			},
		},
		{
			name:  "longest zone wins",
			hosts: []string{"a.sub.x.com", "b.x.com"},
			zones: []string{"x.com", "sub.x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-sub-x-com", Zone: "sub.x.com", DNSNames: []string{"*.sub.x.com"}},
				{Name: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com"}},
			},
		},
		{
			name:  "many hosts collapse to one wildcard",
			hosts: []string{"a.x.com", "b.x.com", "c.x.com", "d.x.com"},
			zones: []string{"x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com"}},
			},
		},
		{
			name:  "an explicit wildcard host is taken as-is",
			hosts: []string{"*.x.com"},
			zones: []string{"x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com"}},
			},
		},
		{
			name:  "case and trailing dots are normalised",
			hosts: []string{"API.X.COM.", "api.x.com"},
			zones: []string{"X.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com"}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plan, err := domain.BuildPlan(domain.PlanInput{Hosts: tc.hosts, Zones: tc.zones})
			if err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			if !reflect.DeepEqual(plan.Certificates, tc.want) {
				t.Errorf("certificates =\n  %+v\nwant\n  %+v", plan.Certificates, tc.want)
			}
		})
	}
}

func TestBuildPlanRejectsPublicSuffixZones(t *testing.T) {
	t.Parallel()
	// The guard that matters most: a misconfigured zone must never be able to
	// request "*.com" or "*.co.uk".
	for _, zone := range []string{"com", "co.uk", "org", "github.io", "*.x.com"} {
		t.Run(zone, func(t *testing.T) {
			t.Parallel()
			_, err := domain.BuildPlan(domain.PlanInput{
				Hosts: []string{"a." + zone},
				Zones: []string{zone},
			})
			if !errors.Is(err, domain.ErrInvalidZone) {
				t.Errorf("expected ErrInvalidZone for zone %q, got %v", zone, err)
			}
		})
	}
}

func TestBuildPlanRequiresZones(t *testing.T) {
	t.Parallel()
	// Without an allowlist, anyone who can create an Ingress could trigger ACME
	// issuance. An empty zone list is a configuration error, not "allow all".
	_, err := domain.BuildPlan(domain.PlanInput{Hosts: []string{"a.x.com"}})
	if !errors.Is(err, domain.ErrInvalidZone) {
		t.Errorf("expected ErrInvalidZone for an empty allowlist, got %v", err)
	}
}

func TestBuildPlanSkipsRatherThanSilentlyDropping(t *testing.T) {
	t.Parallel()
	plan, err := domain.BuildPlan(domain.PlanInput{
		Hosts: []string{"a.x.com", "a.evil.com", "*.*.x.com", "localhost"},
		Zones: []string{"x.com"},
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	want := []domain.SkippedHost{
		{Host: "*.*.x.com", Reason: domain.ReasonMalformed},
		{Host: "a.evil.com", Reason: domain.ReasonOutsideAllowlist},
		{Host: "localhost", Reason: domain.ReasonOutsideAllowlist},
	}
	if !reflect.DeepEqual(plan.Skipped, want) {
		t.Errorf("skipped =\n  %+v\nwant\n  %+v", plan.Skipped, want)
	}
	if len(plan.Certificates) != 1 {
		t.Errorf("certificates = %d, want 1", len(plan.Certificates))
	}
}

func TestBuildPlanEnforcesMaxCertificates(t *testing.T) {
	t.Parallel()
	plan, err := domain.BuildPlan(domain.PlanInput{
		Hosts:           []string{"a.one.com", "a.two.com", "a.three.com"},
		Zones:           []string{"one.com", "two.com", "three.com"},
		MaxCertificates: 2,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Certificates) != 2 {
		t.Fatalf("certificates = %d, want 2", len(plan.Certificates))
	}
	// The overflow must be reported, never dropped in silence.
	if len(plan.Skipped) == 0 {
		t.Fatal("overflow was not reported in Skipped")
	}
	for _, skipped := range plan.Skipped {
		if skipped.Reason != domain.ReasonMaxCertificates {
			t.Errorf("reason = %q, want %q", skipped.Reason, domain.ReasonMaxCertificates)
		}
	}
}

func TestBuildPlanPerWildcardGrouping(t *testing.T) {
	t.Parallel()
	plan, err := domain.BuildPlan(domain.PlanInput{
		Hosts:    []string{"a.x.com", "x.com", "a.sub.x.com"},
		Zones:    []string{"x.com"},
		Grouping: domain.GroupingPerWildcard,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	want := []domain.CertificateRequest{
		{Name: "wildcard-sub-x-com", Zone: "x.com", DNSNames: []string{"*.sub.x.com"}},
		{Name: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com", "x.com"}},
	}
	if !reflect.DeepEqual(plan.Certificates, want) {
		t.Errorf("certificates =\n  %+v\nwant\n  %+v", plan.Certificates, want)
	}
}

func TestBuildPlanIsDeterministic(t *testing.T) {
	t.Parallel()
	// Map iteration must not leak into the output: an unstable plan would churn
	// Certificate resources and mint pointless Key Vault versions.
	input := domain.PlanInput{
		Hosts: []string{"c.x.com", "a.y.com", "b.x.com", "y.com", "a.sub.y.com"},
		Zones: []string{"x.com", "y.com"},
	}
	first, err := domain.BuildPlan(input)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	for i := range 20 {
		next, err := domain.BuildPlan(input)
		if err != nil {
			t.Fatalf("BuildPlan: %v", err)
		}
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("plan differed on iteration %d:\n  %+v\n  %+v", i, first, next)
		}
	}
}

func TestSplitListenerHostnames(t *testing.T) {
	t.Parallel()
	// Application Gateway allows at most five host names per multi-site listener.
	names := []string{"a", "b", "c", "d", "e", "f", "g"}
	got := domain.SplitListenerHostnames(names)

	want := [][]string{{"a", "b", "c", "d", "e"}, {"f", "g"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for _, group := range got {
		if len(group) > domain.MaxListenerHostnames {
			t.Errorf("group %v exceeds the listener cap of %d", group, domain.MaxListenerHostnames)
		}
	}
}

// Discovery answers "what does the cluster route today". That is empty before
// the first workload exists, yet an Application Gateway listener cannot
// reference a Key Vault certificate that does not exist yet -- so a new zone
// could not be wired up at all without this.
func TestBuildPlanIssuesZoneWildcardsWithoutDiscovery(t *testing.T) {
	t.Parallel()
	plan, err := domain.BuildPlan(domain.PlanInput{
		Zones:              []string{"x.com", "xx.x.com"},
		MaxCertificates:    10,
		Grouping:           domain.GroupingPerZone,
		IssueZoneWildcards: true,
		Hosts:              nil, // nothing routed yet
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	got := map[string][]string{}
	for _, cert := range plan.Certificates {
		got[cert.Name] = cert.DNSNames
	}
	want := map[string][]string{
		"wildcard-x-com":    {"*.x.com"},
		"wildcard-xx-x-com": {"*.xx.x.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("certificates = %v, want %v", got, want)
	}
}

// Seeded names are hostnames like any other, so a discovered host under the
// same zone joins the same certificate rather than producing a second one.
func TestBuildPlanMergesSeededWildcardsWithDiscoveredHosts(t *testing.T) {
	t.Parallel()
	plan, err := domain.BuildPlan(domain.PlanInput{
		Zones:              []string{"x.com"},
		MaxCertificates:    10,
		Grouping:           domain.GroupingPerZone,
		IssueZoneWildcards: true,
		// The apex needs its own SAN: "*.x.com" does not match "x.com".
		Hosts: []string{"api.x.com", "x.com"},
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Certificates) != 1 {
		t.Fatalf("certificates = %d, want 1", len(plan.Certificates))
	}
	want := []string{"*.x.com", "x.com"}
	got := slices.Clone(plan.Certificates[0].DNSNames)
	slices.Sort(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dnsNames = %v, want %v", got, want)
	}
}

// The seeding must not become a way around the guards: a zone at or above a
// public suffix is still unreachable, and the cap still applies.
func TestBuildPlanSeedingStillHonoursTheGuards(t *testing.T) {
	t.Parallel()
	if _, err := domain.BuildPlan(domain.PlanInput{
		Zones:              []string{"com"},
		MaxCertificates:    10,
		IssueZoneWildcards: true,
	}); err == nil {
		t.Error("a public-suffix zone must be rejected even when seeding")
	}

	// The cap reports the overflow rather than failing the whole plan, so the
	// certificates that do fit are still issued and the rest are visible.
	plan, err := domain.BuildPlan(domain.PlanInput{
		Zones:              []string{"a.com", "b.com", "c.com"},
		MaxCertificates:    2,
		IssueZoneWildcards: true,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Certificates) != 2 {
		t.Errorf("certificates = %d, want 2 -- the cap must apply to seeded wildcards", len(plan.Certificates))
	}
	if !slices.ContainsFunc(plan.Skipped, func(s domain.SkippedHost) bool {
		return s.Reason == domain.ReasonMaxCertificates
	}) {
		t.Errorf("skipped = %+v, want the overflow reported with ReasonMaxCertificates", plan.Skipped)
	}
}
