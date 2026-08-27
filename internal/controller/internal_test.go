package controller

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/infra/pkcs12"
)

func TestClassify(t *testing.T) {
	t.Parallel()
	notFound := apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "wildcard-tls")

	// The distinction that matters: a problem with the *data* will not fix
	// itself on retry, so backing off exponentially would spin the queue and
	// bury the signal. A transient failure is worth a backoff.
	tests := []struct {
		name          string
		err           error
		wantReason    string
		wantRetryable bool
	}{
		{
			// Normal while cert-manager is still issuing; the Secret watch wakes
			// the controller the moment it appears.
			name:       "source not issued yet",
			err:        fmt.Errorf("loading: %w", notFound),
			wantReason: ReasonSourceNotFound,
		},
		{"expired", fmt.Errorf("x: %w", domain.ErrExpired), ReasonCertificateExpired, false},
		{"not yet valid", domain.ErrNotYetValid, ReasonCertificateExpired, false},
		{"key mismatch", fmt.Errorf("x: %w", domain.ErrKeyMismatch), ReasonSourceInvalid, false},
		{"no certificates", domain.ErrNoCertificates, ReasonSourceInvalid, false},
		{"no private key", domain.ErrNoPrivateKey, ReasonSourceInvalid, false},
		{"unsupported key", domain.ErrUnsupportedKey, ReasonSourceInvalid, false},
		{"no dns names", domain.ErrNoDNSNames, ReasonSourceInvalid, false},
		{"invalid vault name", domain.ErrInvalidVaultName, ReasonConfigInvalid, false},
		{"invalid zone", domain.ErrInvalidZone, ReasonConfigInvalid, false},
		{"invalid host", domain.ErrInvalidHost, ReasonConfigInvalid, false},
		{
			// Key Vault throttling, an API server hiccup, a network blip.
			name:          "transient",
			err:           errors.New("key vault returned 503"),
			wantReason:    ReasonVaultError,
			wantRetryable: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reason, retryable := classify(tc.err)
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
			if retryable != tc.wantRetryable {
				t.Errorf("retryable = %v, want %v", retryable, tc.wantRetryable)
			}
		})
	}
}

func TestJitterStaysWithinTenPercent(t *testing.T) {
	t.Parallel()
	// Requeues are spread so that many resources do not wake together and hit
	// Key Vault's 300-imports-per-10-seconds throttle in one burst. The spread
	// must never shorten the interval, or the resync would drift faster than
	// configured.
	const base = time.Hour
	for range 200 {
		got := jitter(base)
		if got < base {
			t.Fatalf("jitter(%s) = %s, must never be shorter than the interval", base, got)
		}
		if got > base+base/10 {
			t.Fatalf("jitter(%s) = %s, exceeds the 10%% spread", base, got)
		}
	}

	// A non-positive interval must fall back rather than produce a hot loop.
	if got := jitter(0); got != DefaultResyncInterval {
		t.Errorf("jitter(0) = %s, want the default %s", got, DefaultResyncInterval)
	}
	if got := jitter(-time.Minute); got != DefaultResyncInterval {
		t.Errorf("jitter(-1m) = %s, want the default %s", got, DefaultResyncInterval)
	}
}

func TestResyncInterval(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		policy *v1alpha1.SyncPolicySpec
		want   time.Duration
	}{
		{"nil policy", nil, DefaultResyncInterval},
		{"nil interval", &v1alpha1.SyncPolicySpec{}, DefaultResyncInterval},
		{"zero interval", &v1alpha1.SyncPolicySpec{ResyncInterval: &metav1.Duration{}}, DefaultResyncInterval},
		{
			"negative interval",
			&v1alpha1.SyncPolicySpec{ResyncInterval: &metav1.Duration{Duration: -time.Hour}},
			DefaultResyncInterval,
		},
		{
			"explicit interval",
			&v1alpha1.SyncPolicySpec{ResyncInterval: &metav1.Duration{Duration: 15 * time.Minute}},
			15 * time.Minute,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := resyncInterval(tc.policy); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestPKCS12Profile(t *testing.T) {
	t.Parallel()
	// An unset profile must default to legacy, the 3DES/SHA-1 encoding Azure's
	// own guidance asks for by name.
	if got := pkcs12Profile(nil); got != pkcs12.ProfileLegacy {
		t.Errorf("pkcs12Profile(nil) = %q, want legacy", got)
	}
	if got := pkcs12Profile(&v1alpha1.SyncPolicySpec{}); got != "" {
		t.Errorf("pkcs12Profile(empty) = %q, want the empty profile so the encoder defaults", got)
	}
	got := pkcs12Profile(&v1alpha1.SyncPolicySpec{PKCS12Profile: v1alpha1.PKCS12Modern})
	if got != pkcs12.ProfileModern {
		t.Errorf("pkcs12Profile(modern) = %q, want modern", got)
	}
}

func TestVaultTarget(t *testing.T) {
	t.Parallel()
	// The CRD enforces exactly one of the two, but the resolution order still
	// has to be deterministic.
	if got := vaultTarget(v1alpha1.KeyVaultSpec{Name: "my-vault"}); got != "my-vault" {
		t.Errorf("got %q, want my-vault", got)
	}
	spec := v1alpha1.KeyVaultSpec{VaultURL: "https://my-vault.vault.azure.net"}
	if got := vaultTarget(spec); got != "https://my-vault.vault.azure.net" {
		t.Errorf("got %q, want the URL", got)
	}
}

func TestEnabledDefaultsToTrue(t *testing.T) {
	t.Parallel()
	// Discovery sources are opt-out, so an unset field must read as enabled --
	// otherwise a policy with no discovery block would find nothing at all.
	pick := func(d *v1alpha1.DiscoverySpec) *bool { return d.Ingress }

	if !enabled(nil, pick) {
		t.Error("a nil discovery spec should enable ingress discovery")
	}
	if !enabled(&v1alpha1.DiscoverySpec{}, pick) {
		t.Error("an unset field should enable ingress discovery")
	}

	off := false
	if enabled(&v1alpha1.DiscoverySpec{Ingress: &off}, pick) {
		t.Error("an explicit false should disable ingress discovery")
	}
	on := true
	if !enabled(&v1alpha1.DiscoverySpec{Ingress: &on}, pick) {
		t.Error("an explicit true should enable ingress discovery")
	}
}

func TestOrphanVerbDescribesRetentionHonestly(t *testing.T) {
	t.Parallel()
	// Retain is the default because a listener may still be serving the
	// certificate. The status message should say so rather than just "retained".
	retained := orphanVerb(v1alpha1.OrphanRetain)
	if retained == "pruned" {
		t.Fatalf("Retain reported as %q", retained)
	}
	if !contains(retained, "Key Vault certificate is never deleted") {
		t.Errorf("Retain message = %q, want it to state that Key Vault is untouched", retained)
	}
	if got := orphanVerb(v1alpha1.OrphanPrune); got != "pruned" {
		t.Errorf("Prune reported as %q, want pruned", got)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestRecordPlanStaysWithinWhatTheCRDAccepts(t *testing.T) {
	t.Parallel()
	// The API server rejects a status that exceeds the MaxItems on these
	// fields, and a rejected status update is not cosmetic: the policy reports
	// nothing at all, on every pass, until the plan shrinks. Verified against a
	// real API server -- 101 listeners and 101 SANs are both refused.
	const zones = 60
	state := app.DesiredState{DiscoveredHosts: make([]string, 500)}
	for i := range zones {
		// Six SANs is two listeners each, so this alone is past the 100 the
		// field allows -- and past what one gateway can serve.
		sans := make([]string, 6)
		for j := range sans {
			sans[j] = fmt.Sprintf("*.s%d.z%d.com", j, i)
		}
		state.Certificates = append(state.Certificates, app.DesiredCertificate{
			CertificateRequest: domain.CertificateRequest{
				Name:     fmt.Sprintf("wildcard-z%d-com", i),
				Zone:     fmt.Sprintf("z%d.com", i),
				DNSNames: sans,
			},
			SecretName:       "tls",
			SecretIdentifier: "https://v.vault.azure.net/secrets/c",
			Listeners:        domain.SplitListenerHostnames(sans),
		})
	}
	// One certificate carrying more SANs than the report can hold, with the
	// listeners that actually follow from them.
	oversized := make([]string, 150)
	for i := range oversized {
		oversized[i] = fmt.Sprintf("*.wide%d.com", i)
	}
	state.Certificates[0].DNSNames = oversized
	state.Certificates[0].Listeners = domain.SplitListenerHostnames(oversized)

	r := &WildcardCertificatePolicyReconciler{Clock: fixedClock{}}
	policy := &v1alpha1.WildcardCertificatePolicy{}
	r.recordPlan(policy, state)

	if got := len(policy.Status.ApplicationGateway.Listeners); got > maxReportedListeners {
		t.Errorf("reported %d listeners, more than the %d the CRD allows", got, maxReportedListeners)
	}
	// Truncating without saying so would read as "this plan fits on one
	// gateway", which is the opposite of what 120 listeners means.
	// 59 certificates of six SANs (two listeners each) plus one of 150 (thirty).
	if got, want := policy.Status.ApplicationGateway.ListenerCount, int32(59*2+30); got != want {
		t.Errorf("listenerCount = %d, want the true total %d", got, want)
	}
	for _, cert := range policy.Status.RequiredCertificates {
		if got := len(cert.DNSNames); got > maxReportedDNSNames {
			t.Errorf("%s reported %d SANs, more than the %d the CRD allows",
				cert.Name, got, maxReportedDNSNames)
		}
	}
	if got, want := policy.Status.RequiredCertificateCount, int32(zones); got != want {
		t.Errorf("requiredCertificateCount = %d, want %d", got, want)
	}
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1700000000, 0) }

func TestApplyOutcomeDropsTheGaugeOfARenamedCertificate(t *testing.T) {
	// Not parallel: it asserts on package-level metrics.
	//
	// The gauge is labelled by certificate name, so renaming one leaves the old
	// series exported forever -- reporting an expiry that nothing refreshes,
	// which is exactly the signal this metric exists to make trustworthy.
	certificateNotAfter.Reset()
	t.Cleanup(certificateNotAfter.Reset)

	r := &KeyVaultCertificateSyncReconciler{Clock: fixedClock{}}
	sync := &v1alpha1.KeyVaultCertificateSync{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wildcard"},
	}
	notAfter := time.Unix(1700000000, 0)

	r.applyOutcome(sync, app.SyncOutcome{
		Action: domain.ActionImport, CertificateName: "wildcard-x-com", NotAfter: notAfter,
	})
	r.applyOutcome(sync, app.SyncOutcome{
		Action: domain.ActionImport, CertificateName: "wildcard-y-com", NotAfter: notAfter,
	})

	const want = `
# HELP certsync_certificate_not_after_timestamp_seconds Expiry of the synced certificate, in unix seconds.
# TYPE certsync_certificate_not_after_timestamp_seconds gauge
certsync_certificate_not_after_timestamp_seconds{certificate="wildcard-y-com",name="wildcard",namespace="apps"} 1.7e+09
`
	if err := testutil.CollectAndCompare(certificateNotAfter, strings.NewReader(want)); err != nil {
		t.Errorf("the renamed certificate left a stale series behind:\n%v", err)
	}
}
