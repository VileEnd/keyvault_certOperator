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
				{Name: "wildcard-x-com", VaultName: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com"}},
			},
		},
		{
			name:  "apex is added as its own SAN",
			hosts: []string{"api.x.com", "x.com"},
			zones: []string{"x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", VaultName: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com", "x.com"}},
			},
		},
		{
			name:  "deeper host yields a deeper wildcard on the same zone cert",
			hosts: []string{"api.x.com", "a.sub.x.com"},
			zones: []string{"x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", VaultName: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.sub.x.com", "*.x.com"}},
			},
		},
		{
			name:  "longest zone wins",
			hosts: []string{"a.sub.x.com", "b.x.com"},
			zones: []string{"x.com", "sub.x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-sub-x-com", VaultName: "wildcard-sub-x-com", Zone: "sub.x.com", DNSNames: []string{"*.sub.x.com"}},
				{Name: "wildcard-x-com", VaultName: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com"}},
			},
		},
		{
			name:  "many hosts collapse to one wildcard",
			hosts: []string{"a.x.com", "b.x.com", "c.x.com", "d.x.com"},
			zones: []string{"x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", VaultName: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com"}},
			},
		},
		{
			name:  "an explicit wildcard host is taken as-is",
			hosts: []string{"*.x.com"},
			zones: []string{"x.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", VaultName: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com"}},
			},
		},
		{
			name:  "case and trailing dots are normalised",
			hosts: []string{"API.X.COM.", "api.x.com"},
			zones: []string{"X.com"},
			want: []domain.CertificateRequest{
				{Name: "wildcard-x-com", VaultName: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com"}},
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
		{Name: "wildcard-sub-x-com", VaultName: "wildcard-sub-x-com", Zone: "x.com", DNSNames: []string{"*.sub.x.com"}},
		{Name: "wildcard-x-com", VaultName: "wildcard-x-com", Zone: "x.com", DNSNames: []string{"*.x.com", "x.com"}},
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
	// The apex is seeded separately because a wildcard does not cover it, and
	// independently because tying it to IssueZoneWildcards would make setting it
	// alone a silent no-op.
	tests := []struct {
		name      string
		wildcards bool
		apex      bool
		want      map[string][]string
	}{
		{
			name:      "wildcards only",
			wildcards: true,
			want: map[string][]string{
				"wildcard-x-com":    {"*.x.com"},
				"wildcard-xx-x-com": {"*.xx.x.com"},
			},
		},
		{
			name: "apex only",
			apex: true,
			// Named after the SAN it carries: "x-com" holds "x.com", and a
			// listener configured for it is served what it expects.
			want: map[string][]string{
				"x-com":    {"x.com"},
				"xx-x-com": {"xx.x.com"},
			},
		},
		{
			name:      "wildcard and apex share one certificate per zone",
			wildcards: true,
			apex:      true,
			want: map[string][]string{
				"wildcard-x-com":    {"*.x.com", "x.com"},
				"wildcard-xx-x-com": {"*.xx.x.com", "xx.x.com"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plan, err := domain.BuildPlan(domain.PlanInput{
				Zones:              []string{"x.com", "xx.x.com"},
				MaxCertificates:    10,
				Grouping:           domain.GroupingPerZone,
				IssueZoneWildcards: tc.wildcards,
				IssueZoneApex:      tc.apex,
				Hosts:              nil, // nothing routed yet
			})
			if err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}

			got := map[string][]string{}
			for _, cert := range plan.Certificates {
				got[cert.Name] = cert.DNSNames
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("certificates = %v, want %v", got, tc.want)
			}
		})
	}
}

// Seeding an apex must not multiply the certificate count under PerWildcard:
// the apex belongs on the certificate that already carries its zone wildcard.
func TestBuildPlanSeedsTheApexOntoTheZoneWildcardUnderPerWildcard(t *testing.T) {
	t.Parallel()
	plan, err := domain.BuildPlan(domain.PlanInput{
		Zones:              []string{"x.com"},
		MaxCertificates:    10,
		Grouping:           domain.GroupingPerWildcard,
		IssueZoneWildcards: true,
		IssueZoneApex:      true,
		Hosts:              []string{"a.b.x.com"},
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	want := []domain.CertificateRequest{
		{
			Name: "wildcard-b-x-com", VaultName: "wildcard-b-x-com", Zone: "x.com",
			DNSNames: []string{"*.b.x.com"},
		},
		{
			Name: "wildcard-x-com", VaultName: "wildcard-x-com", Zone: "x.com",
			DNSNames: []string{"*.x.com", "x.com"},
		},
	}
	if !reflect.DeepEqual(plan.Certificates, want) {
		t.Errorf("certificates =\n  %+v\nwant\n  %+v", plan.Certificates, want)
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

	// A seeded apex travels the same path, so the cap has to reach it too.
	plan, err = domain.BuildPlan(domain.PlanInput{
		Zones:           []string{"a.com", "b.com", "c.com"},
		MaxCertificates: 2,
		IssueZoneApex:   true,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Certificates) != 2 {
		t.Errorf("certificates = %d, want 2 -- the cap must apply to a seeded apex", len(plan.Certificates))
	}
}

// An adopter's Application Gateway listener already names the Key Vault object
// it serves, and repointing it is a live cutover -- so the operator has to be
// able to write that name rather than the one it would derive.
func TestBuildPlanPinsTheKeyVaultObjectName(t *testing.T) {
	t.Parallel()
	plan, err := domain.BuildPlan(domain.PlanInput{
		Zones:              []string{"x.com", "tm.x.com"},
		MaxCertificates:    10,
		IssueZoneWildcards: true,
		IssueZoneApex:      true,
		// Keys are normalised like any other hostname, so case and a root dot
		// do not decide whether a pin is honoured.
		CertificateNames: map[string]string{"x.com": "ingress-certificate", "TM.X.com.": "TM-certificate"},
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	// Only VaultName follows the pin. Name is what the controller calls the
	// cert-manager Certificate and the sync resource, so moving it would orphan
	// everything this policy has already issued.
	want := []domain.CertificateRequest{
		{
			Name: "wildcard-tm-x-com", VaultName: "TM-certificate", Zone: "tm.x.com",
			DNSNames: []string{"*.tm.x.com", "tm.x.com"},
		},
		{
			Name: "wildcard-x-com", VaultName: "ingress-certificate", Zone: "x.com",
			DNSNames: []string{"*.x.com", "x.com"},
		},
	}
	if !reflect.DeepEqual(plan.Certificates, want) {
		t.Errorf("certificates =\n  %+v\nwant\n  %+v", plan.Certificates, want)
	}
}

// The pin belongs to the zone, not to a SAN, so it holds even where the zone
// wildcard is not covered and the derived name follows a deeper one.
func TestBuildPlanPinsTheZoneCertificateWhateverItIsNamed(t *testing.T) {
	t.Parallel()
	plan, err := domain.BuildPlan(domain.PlanInput{
		Zones:            []string{"x.com"},
		MaxCertificates:  10,
		Hosts:            []string{"a.b.x.com"},
		CertificateNames: map[string]string{"x.com": "ingress-certificate"},
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	want := []domain.CertificateRequest{
		{
			Name: "wildcard-b-x-com", VaultName: "ingress-certificate", Zone: "x.com",
			DNSNames: []string{"*.b.x.com"},
		},
	}
	if !reflect.DeepEqual(plan.Certificates, want) {
		t.Errorf("certificates =\n  %+v\nwant\n  %+v", plan.Certificates, want)
	}
}

// A pin for a zone the cluster does not route yet names nothing, which is not
// the dangerous case: no certificate has been written under the wrong name.
func TestBuildPlanAcceptsAPinForAZoneWithNothingPlanned(t *testing.T) {
	t.Parallel()
	plan, err := domain.BuildPlan(domain.PlanInput{
		Zones:            []string{"x.com"},
		MaxCertificates:  10,
		CertificateNames: map[string]string{"x.com": "ingress-certificate"},
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Certificates) != 0 {
		t.Errorf("certificates = %+v, want none", plan.Certificates)
	}
}

func TestBuildPlanRejectsAnUnusablePin(t *testing.T) {
	t.Parallel()
	// Every one of these is silent if it is not refused: a Key Vault object
	// written under a name no listener reads, or two certificates overwriting
	// each other in one object -- under a policy reporting Ready either way.
	tests := []struct {
		name string
		in   domain.PlanInput
		want error
	}{
		{
			name: "pinned zone is not in the allowlist",
			in: domain.PlanInput{
				Zones: []string{"x.com"}, IssueZoneWildcards: true,
				CertificateNames: map[string]string{"y.com": "ingress-certificate"},
			},
			want: domain.ErrInvalidZone,
		},
		{
			name: "one zone pinned twice",
			in: domain.PlanInput{
				Zones: []string{"x.com"}, IssueZoneWildcards: true,
				CertificateNames: map[string]string{"x.com": "ingress-certificate", "X.com.": "other-certificate"},
			},
			want: domain.ErrInvalidZone,
		},
		{
			name: "a name Azure would reject",
			in: domain.PlanInput{
				Zones: []string{"x.com"}, IssueZoneWildcards: true,
				CertificateNames: map[string]string{"x.com": "ingress_certificate"},
			},
			want: domain.ErrInvalidVaultName,
		},
		{
			name: "two zones pinned to one object",
			in: domain.PlanInput{
				Zones: []string{"x.com", "y.com"}, IssueZoneWildcards: true,
				CertificateNames: map[string]string{"x.com": "ingress-certificate", "y.com": "ingress-certificate"},
			},
			want: domain.ErrInvalidVaultName,
		},
		{
			name: "a pin colliding with another zone's derived name",
			in: domain.PlanInput{
				Zones: []string{"x.com", "y.com"}, IssueZoneWildcards: true,
				CertificateNames: map[string]string{"y.com": "wildcard-x-com"},
			},
			want: domain.ErrInvalidVaultName,
		},
		{
			// Refused rather than guessed: the CRD only accepts pins under
			// PerZone, and picking one of the two here would silently leave the
			// other's certificate on a name nothing serves.
			name: "ambiguous under PerWildcard",
			in: domain.PlanInput{
				Zones: []string{"x.com"}, Grouping: domain.GroupingPerWildcard,
				Hosts:            []string{"a.b.x.com", "a.c.x.com"},
				CertificateNames: map[string]string{"x.com": "ingress-certificate"},
			},
			want: domain.ErrInvalidVaultName,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.BuildPlan(tc.in); !errors.Is(err, tc.want) {
				t.Errorf("BuildPlan() = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestBuildPlanNamesAZoneCertificateAfterWhatItCovers(t *testing.T) {
	t.Parallel()
	// The name is what an Application Gateway listener is configured with, so
	// "wildcard-x-com" has to mean a certificate that actually carries
	// "*.x.com". Naming every zone certificate after its zone made it mean
	// "the certificate for zone x.com", which serves nothing on that listener.
	tests := []struct {
		name  string
		hosts []string
		want  domain.CertificateRequest
	}{
		{
			name:  "no zone wildcard is covered",
			hosts: []string{"a.b.x.com"},
			want: domain.CertificateRequest{
				Name: "wildcard-b-x-com", VaultName: "wildcard-b-x-com", Zone: "x.com", DNSNames: []string{"*.b.x.com"},
			},
		},
		{
			name:  "only the apex is covered",
			hosts: []string{"x.com"},
			want: domain.CertificateRequest{
				Name: "x-com", VaultName: "x-com", Zone: "x.com", DNSNames: []string{"x.com"},
			},
		},
		{
			name:  "the zone wildcard wins when it is covered",
			hosts: []string{"a.x.com", "a.b.x.com", "x.com"},
			want: domain.CertificateRequest{
				Name: "wildcard-x-com", VaultName: "wildcard-x-com", Zone: "x.com",
				DNSNames: []string{"*.b.x.com", "*.x.com", "x.com"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plan, err := domain.BuildPlan(domain.PlanInput{Hosts: tc.hosts, Zones: []string{"x.com"}})
			if err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			want := []domain.CertificateRequest{tc.want}
			if !reflect.DeepEqual(plan.Certificates, want) {
				t.Errorf("certificates =\n  %+v\nwant\n  %+v", plan.Certificates, want)
			}
		})
	}
}

func TestBuildPlanCapNeverEvictsAnIssuedCertificate(t *testing.T) {
	t.Parallel()
	// Reaching the cap must overflow the *new* certificate. Dropping an issued
	// one instead takes it out of the plan, which makes it an orphan, which
	// under orphanPolicy: Prune deletes it -- an outage caused by adding an
	// unrelated zone.
	const cap = 2
	issued := planNames(t, domain.PlanInput{
		Zones: []string{"m.com", "z.com"}, MaxCertificates: cap, IssueZoneWildcards: true,
	})
	if want := []string{"wildcard-m-com", "wildcard-z-com"}; !reflect.DeepEqual(issued, want) {
		t.Fatalf("issued = %v, want %v", issued, want)
	}

	// "b.com" sorts before both, so truncating the sorted plan would drop
	// "wildcard-z-com" -- the certificate the cluster is already serving.
	plan, err := domain.BuildPlan(domain.PlanInput{
		Zones:              []string{"m.com", "z.com", "b.com"},
		MaxCertificates:    cap,
		IssueZoneWildcards: true,
		Existing:           issued,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	got := requestNames(plan.Certificates)
	if !reflect.DeepEqual(got, issued) {
		t.Errorf("certificates = %v, want the already-issued %v", got, issued)
	}
	want := []domain.SkippedHost{{Host: "*.b.com", Reason: domain.ReasonMaxCertificates}}
	if !reflect.DeepEqual(plan.Skipped, want) {
		t.Errorf("skipped = %+v, want %+v", plan.Skipped, want)
	}
}

func TestBuildPlanCapStillFillsFromNothing(t *testing.T) {
	t.Parallel()
	// With nothing issued the cap has no existing certificate to protect, so it
	// takes the plan in order. Without this the fix above could pass by never
	// applying the cap at all.
	got := planNames(t, domain.PlanInput{
		Zones: []string{"m.com", "z.com", "b.com"}, MaxCertificates: 2, IssueZoneWildcards: true,
	})
	if want := []string{"wildcard-b-com", "wildcard-m-com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("certificates = %v, want %v", got, want)
	}
}

func planNames(t *testing.T, in domain.PlanInput) []string {
	t.Helper()
	plan, err := domain.BuildPlan(in)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	return requestNames(plan.Certificates)
}

func requestNames(certs []domain.CertificateRequest) []string {
	out := make([]string, 0, len(certs))
	for _, cert := range certs {
		out = append(out, cert.Name)
	}
	return out
}
