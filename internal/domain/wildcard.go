package domain

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Grouping selects how discovered hostnames are packed into certificates.
type Grouping string

const (
	// GroupingPerZone issues one SAN certificate per zone, covering every
	// wildcard discovered under it plus the apex. This is the default: it keeps
	// the certificate count -- and therefore the Application Gateway listener,
	// site and SSL-certificate count -- as low as possible.
	GroupingPerZone Grouping = "PerZone"
	// GroupingPerWildcard issues one certificate per distinct wildcard.
	GroupingPerWildcard Grouping = "PerWildcard"
)

// MaxListenerHostnames is Application Gateway's hard cap on host names per
// multi-site HTTPS listener. A certificate may carry more SANs than this; the
// names simply have to be spread across several listeners.
const MaxListenerHostnames = 5

// CertificateRequest is one certificate the cluster needs: a name, the zone it
// belongs to, and the SANs it must cover.
type CertificateRequest struct {
	// Name is the Key Vault certificate name and the cert-manager Certificate name.
	Name string
	// Zone is the allowlisted zone this certificate was planned under.
	Zone string
	// DNSNames are the SANs, sorted, e.g. ["*.x.com", "x.com"].
	DNSNames []string
}

// SkippedHost records a hostname that was deliberately not covered, and why.
// Nothing is ever dropped silently: every skip is reported in status.
type SkippedHost struct {
	Host   string
	Reason string
}

// Skip reasons, kept as constants so controllers and tests agree on the text.
const (
	ReasonOutsideAllowlist = "hostname is not inside any configured zone"
	ReasonMalformed        = "hostname is malformed or not a usable wildcard"
	ReasonMaxCertificates  = "maxCertificates reached; certificate not planned"
)

// PlanInput is the whole input to BuildPlan.
type PlanInput struct {
	// Hosts are the hostnames discovered from Ingress and HTTPRoute resources.
	Hosts []string
	// Zones is the required allowlist of DNS zones we may issue inside.
	Zones []string
	// MaxCertificates caps how many certificates may be planned.
	MaxCertificates int
	// Grouping selects the packing strategy; empty means GroupingPerZone.
	Grouping Grouping
}

// Plan is the desired certificate state derived from discovered hostnames.
type Plan struct {
	Certificates []CertificateRequest
	Skipped      []SkippedHost
}

// BuildPlan turns discovered hostnames into the set of certificates to issue.
//
// Discovery-driven issuance is the most dangerous part of this operator: anyone
// who can create an Ingress could otherwise trigger ACME issuance and burn the
// Let's Encrypt rate limits for a registered domain. Three guards apply, and
// none of them are optional:
//
//  1. Zones is a required allowlist. A hostname outside every configured zone is
//     skipped, never issued.
//  2. Every zone is checked against the Public Suffix List, so "com" or "co.uk"
//     can never become "*.com" or "*.co.uk".
//  3. MaxCertificates caps the plan; the overflow is reported, not issued.
//
// Wildcards match exactly one label, so "*.x.com" covers "a.x.com" but neither
// "x.com" nor "a.b.x.com". The apex is therefore added as its own SAN, and a
// deeper hostname yields a wildcard for its immediate parent.
func BuildPlan(in PlanInput) (Plan, error) {
	zones, err := normalizeZones(in.Zones)
	if err != nil {
		return Plan{}, err
	}

	var plan Plan
	// zone -> set of required DNS names
	required := map[string]map[string]struct{}{}

	for _, raw := range in.Hosts {
		host := NormalizeHost(raw)
		if host == "" {
			continue
		}

		zone, ok := longestMatchingZone(host, zones)
		if !ok {
			plan.Skipped = append(plan.Skipped, SkippedHost{Host: host, Reason: ReasonOutsideAllowlist})
			continue
		}

		name, err := requiredName(host, zone)
		if err != nil {
			plan.Skipped = append(plan.Skipped, SkippedHost{Host: host, Reason: ReasonMalformed})
			continue
		}

		if required[zone] == nil {
			required[zone] = map[string]struct{}{}
		}
		required[zone][name] = struct{}{}
	}

	grouping := in.Grouping
	if grouping == "" {
		grouping = GroupingPerZone
	}
	certs, err := group(required, grouping)
	if err != nil {
		return Plan{}, err
	}

	certs, overflow := applyLimit(certs, in.MaxCertificates)
	for _, cert := range overflow {
		for _, name := range cert.DNSNames {
			plan.Skipped = append(plan.Skipped, SkippedHost{Host: name, Reason: ReasonMaxCertificates})
		}
	}

	plan.Certificates = certs
	sortSkipped(plan.Skipped)
	return plan, nil
}

// requiredName maps one discovered hostname to the SAN that must cover it.
func requiredName(host, zone string) (string, error) {
	if wildcard, ok := strings.CutPrefix(host, "*."); ok {
		// An explicit wildcard is taken as-is, provided the rest is a plain
		// hostname inside the zone.
		if strings.Contains(wildcard, "*") || !withinZone(wildcard, zone) {
			return "", ErrInvalidHost
		}
		return host, nil
	}
	if strings.Contains(host, "*") {
		return "", ErrInvalidHost
	}
	if host == zone {
		// The apex: "*.x.com" does not match "x.com", so it needs its own SAN.
		return host, nil
	}
	// A wildcard covers exactly one label, so the covering name is the parent.
	_, parent, ok := strings.Cut(host, ".")
	if !ok || parent == "" {
		return "", ErrInvalidHost
	}
	return "*." + parent, nil
}

// group packs required SANs into certificates.
func group(required map[string]map[string]struct{}, grouping Grouping) ([]CertificateRequest, error) {
	var certs []CertificateRequest

	zones := make([]string, 0, len(required))
	for zone := range required {
		zones = append(zones, zone)
	}
	sort.Strings(zones)

	for _, zone := range zones {
		names := sortedKeys(required[zone])
		switch grouping {
		case GroupingPerZone:
			cert, err := newRequest(zone, "*."+zone, names)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		case GroupingPerWildcard:
			apexes, wildcards := partitionApex(names)
			for _, wildcard := range wildcards {
				members := []string{wildcard}
				// Attach the apex to the wildcard that shares its domain, so
				// "x.com" rides along on the "*.x.com" certificate.
				if apex, ok := strings.CutPrefix(wildcard, "*."); ok {
					if contains(apexes, apex) {
						members = append(members, apex)
						apexes = remove(apexes, apex)
					}
				}
				cert, err := newRequest(zone, wildcard, members)
				if err != nil {
					return nil, err
				}
				certs = append(certs, cert)
			}
			for _, apex := range apexes {
				cert, err := newRequest(zone, apex, []string{apex})
				if err != nil {
					return nil, err
				}
				certs = append(certs, cert)
			}
		default:
			return nil, fmt.Errorf("unknown grouping %q", grouping)
		}
	}

	sort.SliceStable(certs, func(i, j int) bool { return certs[i].Name < certs[j].Name })
	return resolveNameCollisions(certs), nil
}

func newRequest(zone, nameSeed string, dnsNames []string) (CertificateRequest, error) {
	name, err := DeriveVaultCertificateName(nameSeed)
	if err != nil {
		return CertificateRequest{}, err
	}
	sorted := append([]string(nil), dnsNames...)
	sort.Strings(sorted)
	return CertificateRequest{Name: name, Zone: zone, DNSNames: sorted}, nil
}

// resolveNameCollisions makes derived names unique. The "." to "-" mapping is
// not injective, so "foo.example.com" and "foo-example.com" would otherwise
// share a Key Vault object.
func resolveNameCollisions(certs []CertificateRequest) []CertificateRequest {
	seen := map[string]int{}
	for i, cert := range certs {
		if n := seen[cert.Name]; n > 0 {
			certs[i].Name = DisambiguateVaultName(cert.Name, strings.Join(cert.DNSNames, ","))
		}
		seen[cert.Name]++
	}
	return certs
}

func applyLimit(certs []CertificateRequest, max int) (kept, overflow []CertificateRequest) {
	if max <= 0 || len(certs) <= max {
		return certs, nil
	}
	return certs[:max], certs[max:]
}

// normalizeZones lowercases, de-duplicates and validates the allowlist.
func normalizeZones(zones []string) ([]string, error) {
	if len(zones) == 0 {
		return nil, fmt.Errorf("%w: at least one zone is required", ErrInvalidZone)
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(zones))
	for _, raw := range zones {
		zone := NormalizeHost(raw)
		if zone == "" {
			return nil, fmt.Errorf("%w: empty zone", ErrInvalidZone)
		}
		if err := checkIssuable(zone); err != nil {
			return nil, err
		}
		if _, dup := seen[zone]; dup {
			continue
		}
		seen[zone] = struct{}{}
		out = append(out, zone)
	}
	// Longest first, so "sub.x.com" wins over "x.com" for "a.sub.x.com".
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out, nil
}

// checkIssuable rejects zones at or above a public suffix, which is what stops
// a misconfiguration from ever requesting "*.com" or "*.co.uk".
func checkIssuable(zone string) error {
	if strings.Contains(zone, "*") {
		return fmt.Errorf("%w: %q must not contain a wildcard", ErrInvalidZone, zone)
	}
	suffix, _ := publicsuffix.PublicSuffix(zone)
	if zone == suffix {
		return fmt.Errorf("%w: %q is a public suffix; refusing to issue wildcards for it", ErrInvalidZone, zone)
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(zone); err != nil {
		return fmt.Errorf("%w: %q is not a registrable domain: %w", ErrInvalidZone, zone, err)
	}
	return nil
}

func longestMatchingZone(host string, zones []string) (string, bool) {
	// zones is pre-sorted longest-first.
	candidate := strings.TrimPrefix(host, "*.")
	for _, zone := range zones {
		if withinZone(candidate, zone) {
			return zone, true
		}
	}
	return "", false
}

func withinZone(host, zone string) bool {
	return host == zone || strings.HasSuffix(host, "."+zone)
}

// SplitListenerHostnames chunks SANs into Application Gateway listener-sized
// groups, honouring the five-host-names-per-listener cap.
func SplitListenerHostnames(names []string) [][]string {
	var out [][]string
	for start := 0; start < len(names); start += MaxListenerHostnames {
		end := min(start+MaxListenerHostnames, len(names))
		out = append(out, append([]string(nil), names[start:end]...))
	}
	return out
}

func partitionApex(names []string) (apexes, wildcards []string) {
	for _, name := range names {
		if strings.HasPrefix(name, "*.") {
			wildcards = append(wildcards, name)
		} else {
			apexes = append(apexes, name)
		}
	}
	return apexes, wildcards
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sortSkipped(skipped []SkippedHost) {
	sort.SliceStable(skipped, func(i, j int) bool {
		if skipped[i].Host != skipped[j].Host {
			return skipped[i].Host < skipped[j].Host
		}
		return skipped[i].Reason < skipped[j].Reason
	})
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func remove(list []string, drop string) []string {
	out := list[:0]
	for _, item := range list {
		if item != drop {
			out = append(out, item)
		}
	}
	return out
}
