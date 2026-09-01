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
	// Name identifies the certificate inside the cluster: the cert-manager
	// Certificate, the Secret it writes and the sync resource generated for it
	// are all named after this. It is always derived from the SANs.
	Name string
	// VaultName is the Key Vault object the certificate is imported into. It is
	// Name unless PlanInput.CertificateNames pinned a name for the zone.
	VaultName string
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
	// Existing names the certificates that have already been issued.
	//
	// It changes nothing until MaxCertificates is reached, and then decides
	// which certificates keep their slot: an existing one is never evicted to
	// make room for a new one. Without that, adding a zone whose name sorts
	// early would push an unrelated certificate out of the plan -- and under
	// orphanPolicy: Prune, out of the plan means deleted.
	Existing []string
	// Grouping selects the packing strategy; empty means GroupingPerZone.
	Grouping Grouping
	// IssueZoneWildcards plans "*.zone" for every configured zone, whether or
	// not anything in the cluster routes a name under it.
	//
	// Discovery alone cannot express "this gateway must always serve *.x.com".
	// It answers "what does the cluster route today", which is empty before the
	// first workload exists -- and Application Gateway needs the certificate in
	// Key Vault *before* a listener can reference it. That ordering makes the
	// discovered-only behaviour a chicken-and-egg problem for a new zone.
	//
	// The seeded names go through exactly the same guards as a discovered one:
	// the zone allowlist, the public-suffix check and the certificate cap.
	IssueZoneWildcards bool
	// IssueZoneApex seeds the bare zone, so "x.com" is covered as well as
	// "*.x.com".
	//
	// A wildcard matches exactly one label and so never covers its own apex.
	// Leaving the apex to discovery makes an unrelated routing object
	// load-bearing: deleting it re-issues the certificate without the apex SAN,
	// under the Key Vault object name the gateway is already serving.
	//
	// Independent of IssueZoneWildcards: each flag seeds its own name.
	IssueZoneApex bool
	// CertificateNames pins the Key Vault object name for a zone, keyed by zone.
	//
	// The derived name is right for a cluster this operator set up and wrong for
	// one it is adopting, where an Application Gateway listener already names
	// the object it serves and cannot be repointed without a cutover. Only
	// CertificateRequest.VaultName follows the pin; Name stays derived, so
	// pinning never renames -- and therefore never orphans -- resources the
	// cluster already holds.
	CertificateNames map[string]string
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

	hosts := in.Hosts
	if in.IssueZoneWildcards || in.IssueZoneApex {
		// Seeded rather than special-cased downstream: "*.zone" is a hostname
		// like any other, so it picks up the guards, the grouping and the
		// naming without a second code path that could drift from the first.
		seeded := make([]string, 0, 2*len(zones)+len(hosts))
		for _, zone := range zones {
			if in.IssueZoneWildcards {
				seeded = append(seeded, "*."+zone)
			}
			if in.IssueZoneApex {
				seeded = append(seeded, zone)
			}
		}
		hosts = append(seeded, hosts...)
	}

	for _, raw := range hosts {
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

	certs, overflow := applyLimit(certs, in.MaxCertificates, in.Existing)
	for _, cert := range overflow {
		for _, name := range cert.DNSNames {
			plan.Skipped = append(plan.Skipped, SkippedHost{Host: name, Reason: ReasonMaxCertificates})
		}
	}

	// After the cap, so an overflowed certificate -- which is never written --
	// cannot claim a pinned name or collide with one.
	if err := settleVaultNames(certs, in.CertificateNames, zones); err != nil {
		return Plan{}, err
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
			cert, err := newRequest(zone, perZoneNameSeed(zone, names), names)
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

// perZoneNameSeed picks the SAN a zone certificate should be named after.
//
// The zone's own wildcard wins when it is covered, which is the ordinary case
// and keeps the name an Application Gateway listener is already configured
// with. Naming after the zone unconditionally would be a lie whenever
// "*.<zone>" is not actually a SAN: a certificate holding only "*.b.x.com"
// would still be called "wildcard-x-com", and wiring that onto an "*.x.com"
// listener fails every request the listener accepts.
//
// The consequence to know about is that discovering "*.<zone>" later renames
// the certificate, leaving the old one as an orphan. Setting
// issueZoneWildcards pins the name, because the zone wildcard is then always
// covered. PlanInput.CertificateNames pins the Key Vault object name instead,
// which keeps a rename inside the cluster: the vault object the gateway serves
// stays the same one and keeps being updated.
func perZoneNameSeed(zone string, names []string) string {
	if wildcard := "*." + zone; contains(names, wildcard) {
		return wildcard
	}
	// PrimaryDNSName already prefers a wildcard over a plain name and breaks
	// ties by sort order, which is exactly the choice to make here too.
	return PrimaryDNSName(names)
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
	seen := map[string]struct{}{}
	for i, cert := range certs {
		name := cert.Name
		if _, taken := seen[name]; taken {
			name = DisambiguateVaultName(name, strings.Join(cert.DNSNames, ","))
		}
		// Registered under the name actually used, not the one it collided
		// with, so a disambiguated name cannot silently collide in its turn.
		seen[name] = struct{}{}
		certs[i].Name = name
	}
	return certs
}

// settleVaultNames decides the Key Vault object name of every planned
// certificate: the derived name, or the one the policy pinned for its zone.
//
// Pinning exists for adoption. A gateway that already serves
// "ingress-certificate" cannot be repointed at "wildcard-x-com" without a
// cutover, so the operator has to be able to write the name that is already
// wired up. Only the vault name moves: Name keeps identifying the cluster-side
// resources, because renaming those would orphan every certificate already
// issued.
//
// It runs after resolveNameCollisions, so the derived names it starts from are
// the final ones, and after applyLimit, so an overflowed certificate cannot
// take a pin or collide with one.
func settleVaultNames(certs []CertificateRequest, pinned map[string]string, zones []string) error {
	for i := range certs {
		certs[i].VaultName = certs[i].Name
	}

	overrides, err := normalizePins(pinned, zones)
	if err != nil {
		return err
	}
	for _, zone := range sortedKeys(overrides) {
		target, err := pinTarget(certs, zone)
		if err != nil {
			return err
		}
		// A zone with nothing planned has no certificate to name. That is not an
		// error: it is a zone the cluster does not route yet, and nothing has
		// been written under the wrong name. IssueZoneWildcards makes the zone's
		// certificate exist regardless of discovery.
		if target >= 0 {
			certs[target].VaultName = overrides[zone]
		}
	}
	return distinctVaultNames(certs)
}

// normalizePins validates the pinned names and keys them by normalized zone.
func normalizePins(pinned map[string]string, zones []string) (map[string]string, error) {
	if len(pinned) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(pinned))
	// Sorted, so a configuration with several problems always reports the same
	// one rather than whichever the map happened to yield first.
	for _, raw := range sortedKeys(pinned) {
		zone := NormalizeHost(raw)
		if !contains(zones, zone) {
			return nil, fmt.Errorf("%w: %q is pinned a certificate name but is not a configured zone",
				ErrInvalidZone, raw)
		}
		if _, dup := out[zone]; dup {
			// "X.com" and "x.com" are one zone, so accepting both would make
			// which name wins depend on map iteration order.
			return nil, fmt.Errorf("%w: %q is pinned a certificate name more than once", ErrInvalidZone, zone)
		}
		if err := ValidateVaultCertificateName(pinned[raw]); err != nil {
			return nil, fmt.Errorf("certificate name pinned for %q: %w", raw, err)
		}
		out[zone] = pinned[raw]
	}
	return out, nil
}

// pinTarget picks the certificate a zone's pinned name applies to, or -1 when
// the zone has none planned.
//
// PerZone plans exactly one certificate per zone, which is why the CRD only
// accepts pins under that grouping. The lookup still handles the general case:
// the zone's own wildcard is the certificate a listener configured for the zone
// expects, and anything beyond that is genuinely ambiguous -- two certificates
// cannot share one Key Vault object, so guessing would silently overwrite one
// with the other on every reconcile.
func pinTarget(certs []CertificateRequest, zone string) (int, error) {
	target, planned := -1, 0
	for i, cert := range certs {
		if cert.Zone != zone {
			continue
		}
		if contains(cert.DNSNames, "*."+zone) {
			return i, nil
		}
		planned++
		target = i
	}
	if planned > 1 {
		return -1, fmt.Errorf("%w: %q is pinned a certificate name, but %d certificates are planned for it "+
			"and none covers %q", ErrInvalidVaultName, zone, planned, "*."+zone)
	}
	return target, nil
}

// distinctVaultNames refuses a plan in which two certificates would import into
// one Key Vault object. The object would hold whichever was written last and
// the listener serving it would flap between them, so this fails the plan
// rather than issuing something that cannot work.
func distinctVaultNames(certs []CertificateRequest) error {
	seen := make(map[string]string, len(certs))
	for _, cert := range certs {
		if other, taken := seen[cert.VaultName]; taken {
			return fmt.Errorf("%w: %q and %q would both be imported as %q",
				ErrInvalidVaultName, other, cert.Name, cert.VaultName)
		}
		seen[cert.VaultName] = cert.Name
	}
	return nil
}

// applyLimit enforces MaxCertificates, preferring certificates that already
// exist over ones that would be new.
//
// Truncating the sorted plan instead is what the cap used to do, and it evicts
// whichever name happens to sort last. That is a silent outage under
// orphanPolicy: Prune -- the evicted certificate is no longer in the plan, so
// it is an orphan, so it is deleted -- triggered by adding an unrelated zone.
// Overflowing the *new* certificate says the same thing ("you are at the cap")
// without taking down something the cluster is already serving.
func applyLimit(certs []CertificateRequest, max int, existing []string) (kept, overflow []CertificateRequest) {
	if max <= 0 || len(certs) <= max {
		return certs, nil
	}

	issued := make(map[string]struct{}, len(existing))
	for _, name := range existing {
		issued[name] = struct{}{}
	}

	// Two passes over the already-sorted plan: existing certificates claim
	// their slots first, then whatever room is left goes to new ones. Both walk
	// the plan in order, so lowering MaxCertificates drops deterministically
	// rather than arbitrarily.
	keep := make(map[string]struct{}, max)
	for _, cert := range certs {
		if len(keep) == max {
			break
		}
		if _, ok := issued[cert.Name]; ok {
			keep[cert.Name] = struct{}{}
		}
	}
	for _, cert := range certs {
		if len(keep) == max {
			break
		}
		keep[cert.Name] = struct{}{}
	}

	for _, cert := range certs {
		if _, ok := keep[cert.Name]; ok {
			kept = append(kept, cert)
		} else {
			overflow = append(overflow, cert)
		}
	}
	return kept, overflow
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

func sortedKeys[V any](set map[string]V) []string {
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
