package controller_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/controller"
)

func newIngress(namespace, name string, hosts ...string) *networkingv1.Ingress {
	rules := make([]networkingv1.IngressRule, 0, len(hosts))
	for _, host := range hosts {
		rules = append(rules, networkingv1.IngressRule{Host: host})
	}
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       networkingv1.IngressSpec{Rules: rules},
	}
}

func TestPolicyDiscoversHostsAndIssuesOneWildcardPerZone(t *testing.T) {
	requireEnvtest(t)
	ctx := t.Context()
	const apps = "policy-apps"
	const certs = "policy-certs"

	for _, ns := range []string{apps, certs} {
		if err := k8sClient.Create(ctx, newNamespace(ns)); err != nil {
			t.Fatalf("creating namespace %s: %v", ns, err)
		}
	}

	// Four hosts inside the zone plus one outside it. The four must collapse
	// onto a single certificate; the fifth must be reported, not issued.
	ingress := newIngress(apps, "shop",
		"api.discovery.com", "web.discovery.com", "discovery.com", "a.sub.discovery.com", "a.evil.com")
	if err := k8sClient.Create(ctx, ingress); err != nil {
		t.Fatalf("creating ingress: %v", err)
	}

	policy := &v1alpha1.WildcardCertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "discovery"},
		Spec: v1alpha1.WildcardCertificatePolicySpec{
			Zones:                []string{"discovery.com"},
			MaxCertificates:      10,
			Grouping:             v1alpha1.GroupingPerZone,
			IssuerRef:            v1alpha1.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: certs,
			KeyVault:             v1alpha1.KeyVaultSpec{Name: "my-vault"},
			OrphanPolicy:         v1alpha1.OrphanRetain,
		},
	}
	if err := k8sClient.Create(ctx, policy); err != nil {
		t.Fatalf("creating policy: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, policy) })

	certKey := client.ObjectKey{Namespace: certs, Name: "wildcard-discovery-com"}

	eventually(t, 30*time.Second, func() error {
		var cert cmapi.Certificate
		if err := k8sClient.Get(ctx, certKey, &cert); err != nil {
			return err
		}
		// "*.discovery.com" covers neither the apex nor a two-label-deeper host,
		// so all three names have to be present on the certificate.
		want := []string{"*.discovery.com", "*.sub.discovery.com", "discovery.com"}
		got := slices.Clone(cert.Spec.DNSNames)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			return fmt.Errorf("dnsNames = %v, want %v", got, want)
		}
		if cert.Spec.IssuerRef.Name != "letsencrypt-dns" {
			return fmt.Errorf("issuerRef = %+v", cert.Spec.IssuerRef)
		}
		// Key Vault accepts only PKCS#8 private keys.
		if cert.Spec.PrivateKey == nil || cert.Spec.PrivateKey.Encoding != cmapi.PKCS8 {
			return fmt.Errorf("private key encoding = %+v, want PKCS8", cert.Spec.PrivateKey)
		}
		// Without this label on the *Secret*, the issued certificate would fall
		// outside the operator's label-scoped cache and never be synced.
		if cert.Spec.SecretTemplate == nil ||
			cert.Spec.SecretTemplate.Labels[v1alpha1.LabelManaged] != v1alpha1.LabelManagedValue {
			return fmt.Errorf("secretTemplate does not carry the managed label: %+v", cert.Spec.SecretTemplate)
		}
		return nil
	})

	// The policy also generates the sync resource that pushes the certificate on
	// to Key Vault once cert-manager has issued it.
	eventually(t, 30*time.Second, func() error {
		var sync v1alpha1.KeyVaultCertificateSync
		if err := k8sClient.Get(ctx, certKey, &sync); err != nil {
			return err
		}
		if sync.Spec.Source.SecretRef.Name != "wildcard-discovery-com-tls" {
			return fmt.Errorf("secretRef = %q", sync.Spec.Source.SecretRef.Name)
		}
		if sync.Spec.KeyVault.CertificateName != "wildcard-discovery-com" {
			return fmt.Errorf("certificateName = %q", sync.Spec.KeyVault.CertificateName)
		}
		return nil
	})

	eventually(t, 30*time.Second, func() error {
		var got v1alpha1.WildcardCertificatePolicy
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &got); err != nil {
			return err
		}
		if !meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionReady) {
			return fmt.Errorf("not ready: %+v", got.Status.Conditions)
		}
		if len(got.Status.RequiredCertificates) != 1 {
			return fmt.Errorf("requiredCertificates = %d, want 1", len(got.Status.RequiredCertificates))
		}
		// A host outside the allowlist is reported with a reason rather than
		// silently dropped -- otherwise a typo looks identical to a policy that
		// simply does not cover a site.
		if !slices.ContainsFunc(got.Status.SkippedHosts, func(h v1alpha1.SkippedHost) bool {
			return h.Host == "a.evil.com"
		}) {
			return fmt.Errorf("skippedHosts = %+v, want it to include a.evil.com", got.Status.SkippedHosts)
		}
		// The listener guidance is the bridge to the part we deliberately do not
		// automate: the operator holds no ARM permissions.
		if got.Status.ApplicationGateway == nil || len(got.Status.ApplicationGateway.Listeners) != 1 {
			return fmt.Errorf("applicationGateway = %+v", got.Status.ApplicationGateway)
		}
		listener := got.Status.ApplicationGateway.Listeners[0]
		if len(listener.Hostnames) > 5 {
			return fmt.Errorf("listener has %d hostnames, exceeding Application Gateway's cap of 5",
				len(listener.Hostnames))
		}
		want := "https://my-vault.vault.azure.net/secrets/wildcard-discovery-com"
		if listener.KeyVaultSecretID != want {
			return fmt.Errorf("keyVaultSecretID = %q, want %q", listener.KeyVaultSecretID, want)
		}
		return nil
	})

	// Removing the last Ingress for a zone must not remove the certificate.
	// Application Gateway may still be serving it, and deleting it would take the
	// listener down -- so Retain is the default and it has to mean something.
	if err := k8sClient.Delete(ctx, ingress); err != nil {
		t.Fatalf("deleting ingress: %v", err)
	}
	consistently(t, 3*time.Second, func() error {
		var cert cmapi.Certificate
		if err := k8sClient.Get(ctx, certKey, &cert); err != nil {
			return fmt.Errorf("certificate disappeared under the Retain policy: %w", err)
		}
		return nil
	})
}

func TestPolicyRejectsAPublicSuffixZone(t *testing.T) {
	requireEnvtest(t)
	ctx := t.Context()
	const certs = "policy-psl-certs"

	if err := k8sClient.Create(ctx, newNamespace(certs)); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}

	// The guard that matters most. If a public suffix were accepted as a zone,
	// the operator would ask Let's Encrypt for "*.com".
	policy := &v1alpha1.WildcardCertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "public-suffix"},
		Spec: v1alpha1.WildcardCertificatePolicySpec{
			Zones:                []string{"com"},
			MaxCertificates:      10,
			IssuerRef:            v1alpha1.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: certs,
			KeyVault:             v1alpha1.KeyVaultSpec{Name: "my-vault"},
		},
	}
	if err := k8sClient.Create(ctx, policy); err != nil {
		t.Fatalf("creating policy: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, policy) })

	eventually(t, 30*time.Second, func() error {
		var got v1alpha1.WildcardCertificatePolicy
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &got); err != nil {
			return err
		}
		condition := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionReady)
		if condition == nil || condition.Status != metav1.ConditionFalse {
			return fmt.Errorf("Ready = %+v, want False", condition)
		}
		if len(got.Status.RequiredCertificates) != 0 {
			return fmt.Errorf("planned %d certificates for a public suffix zone, want 0",
				len(got.Status.RequiredCertificates))
		}
		return nil
	})

	var certList cmapi.CertificateList
	if err := k8sClient.List(ctx, &certList, client.InNamespace(certs)); err != nil {
		t.Fatalf("listing certificates: %v", err)
	}
	if len(certList.Items) != 0 {
		t.Errorf("created %d certificates for a public suffix zone, want 0", len(certList.Items))
	}
}

func TestPolicyPrunesOnlyWhenAskedAndNeverTouchesKeyVault(t *testing.T) {
	requireEnvtest(t)
	ctx := t.Context()
	const apps = "prune-apps"
	const certs = "prune-certs"

	for _, ns := range []string{apps, certs} {
		if err := k8sClient.Create(ctx, newNamespace(ns)); err != nil {
			t.Fatalf("creating namespace %s: %v", ns, err)
		}
	}

	ingress := newIngress(apps, "both", "a.alpha.com", "a.beta.com")
	if err := k8sClient.Create(ctx, ingress); err != nil {
		t.Fatalf("creating ingress: %v", err)
	}

	policy := &v1alpha1.WildcardCertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "pruning"},
		Spec: v1alpha1.WildcardCertificatePolicySpec{
			Zones:                []string{"alpha.com", "beta.com"},
			MaxCertificates:      10,
			Grouping:             v1alpha1.GroupingPerZone,
			IssuerRef:            v1alpha1.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: certs,
			KeyVault:             v1alpha1.KeyVaultSpec{Name: "my-vault"},
			OrphanPolicy:         v1alpha1.OrphanPrune,
		},
	}
	if err := k8sClient.Create(ctx, policy); err != nil {
		t.Fatalf("creating policy: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, policy) })

	betaKey := client.ObjectKey{Namespace: certs, Name: "wildcard-beta-com"}
	alphaKey := client.ObjectKey{Namespace: certs, Name: "wildcard-alpha-com"}

	eventually(t, 30*time.Second, func() error {
		for _, key := range []client.ObjectKey{alphaKey, betaKey} {
			var cert cmapi.Certificate
			if err := k8sClient.Get(ctx, key, &cert); err != nil {
				return err
			}
		}
		return nil
	})

	// Pretend the beta certificate reached Key Vault, so the test can assert the
	// vault survives the prune.
	testVault.seed("wildcard-beta-com")

	// beta.com loses its last hostname.
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current networkingv1.Ingress
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(ingress), &current); err != nil {
			return err
		}
		current.Spec.Rules = []networkingv1.IngressRule{{Host: "a.alpha.com"}}
		return k8sClient.Update(ctx, &current)
	}); err != nil {
		t.Fatalf("narrowing the ingress: %v", err)
	}

	// Under Prune the generated Kubernetes resources go away...
	eventually(t, 30*time.Second, func() error {
		var cert cmapi.Certificate
		if err := k8sClient.Get(ctx, betaKey, &cert); err == nil {
			return fmt.Errorf("certificate still present")
		} else if !apierrors.IsNotFound(err) {
			return err
		}
		var sync v1alpha1.KeyVaultCertificateSync
		if err := k8sClient.Get(ctx, betaKey, &sync); err == nil {
			return fmt.Errorf("sync resource still present")
		} else if !apierrors.IsNotFound(err) {
			return err
		}
		return nil
	})

	// ...but the Key Vault certificate is still deliberately left in place, under
	// either policy. An Application Gateway listener may still be serving it.
	if !testVault.exists("wildcard-beta-com") {
		t.Error("pruning removed the Key Vault certificate; it must never be deleted")
	}

	// The still-required certificate must survive untouched.
	var alpha cmapi.Certificate
	if err := k8sClient.Get(ctx, alphaKey, &alpha); err != nil {
		t.Errorf("the still-required certificate was removed: %v", err)
	}
}

// Pruning is judged entirely against the current discovery pass. A pass that
// succeeds while finding nothing is indistinguishable from a misconfigured one
// -- a namespaceSelector matching no namespace, or every source switched off --
// and acting on it deletes every generated Certificate, which destroys the
// issued Secret and costs a fresh issuance against Let's Encrypt's duplicate
// limit to recover.
func TestPolicyWithholdsPruningWhenDiscoveryFindsNothing(t *testing.T) {
	requireEnvtest(t)
	ctx := t.Context()
	const apps = "withhold-apps"
	const certs = "withhold-certs"

	for _, ns := range []string{apps, certs} {
		if err := k8sClient.Create(ctx, newNamespace(ns)); err != nil {
			t.Fatalf("creating namespace %s: %v", ns, err)
		}
	}

	ingress := newIngress(apps, "only", "a.withhold.com")
	if err := k8sClient.Create(ctx, ingress); err != nil {
		t.Fatalf("creating ingress: %v", err)
	}

	policy := &v1alpha1.WildcardCertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "withholding"},
		Spec: v1alpha1.WildcardCertificatePolicySpec{
			Zones:                []string{"withhold.com"},
			MaxCertificates:      10,
			Grouping:             v1alpha1.GroupingPerZone,
			IssuerRef:            v1alpha1.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: certs,
			KeyVault:             v1alpha1.KeyVaultSpec{Name: "my-vault"},
			OrphanPolicy:         v1alpha1.OrphanPrune,
		},
	}
	if err := k8sClient.Create(ctx, policy); err != nil {
		t.Fatalf("creating policy: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, policy) })

	key := client.ObjectKey{Namespace: certs, Name: "wildcard-withhold-com"}
	eventually(t, 30*time.Second, func() error {
		var cert cmapi.Certificate
		return k8sClient.Get(ctx, key, &cert)
	})

	// Remove the only routed hostname, so the next pass plans nothing at all.
	if err := k8sClient.Delete(ctx, ingress); err != nil {
		t.Fatalf("deleting ingress: %v", err)
	}

	// The policy must notice and say so...
	eventually(t, 30*time.Second, func() error {
		var got v1alpha1.WildcardCertificatePolicy
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &got); err != nil {
			return err
		}
		condition := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionReady)
		if condition == nil || condition.Reason != controller.ReasonPruneWithheld {
			return fmt.Errorf("Ready condition = %+v, want reason %s", condition, controller.ReasonPruneWithheld)
		}
		return nil
	})

	// ...and crucially, must not have deleted anything. Checked after the
	// condition so a slow prune cannot pass by racing the assertion.
	var cert cmapi.Certificate
	if err := k8sClient.Get(ctx, key, &cert); err != nil {
		t.Errorf("the generated Certificate was deleted on an empty discovery pass: %v", err)
	}
	var sync v1alpha1.KeyVaultCertificateSync
	if err := k8sClient.Get(ctx, key, &sync); err != nil {
		t.Errorf("the generated sync resource was deleted on an empty discovery pass: %v", err)
	}
}

// A source the policy explicitly asked for but which the operator could not
// watch makes the discovered set partial by construction, so pruning against it
// is unsafe even when the plan is not empty.
//
// Only an explicit "true" counts. The CRD defaults these to true, so treating
// the effective value as a requirement would withhold pruning on every cluster
// that does not run Gateway API -- which is most of them.
func TestPolicyWithholdsPruningWhenAnExplicitlyRequestedSourceIsUnavailable(t *testing.T) {
	requireEnvtest(t)
	ctx := t.Context()
	const apps = "withhold-src-apps"
	const certs = "withhold-src-certs"

	for _, ns := range []string{apps, certs} {
		if err := k8sClient.Create(ctx, newNamespace(ns)); err != nil {
			t.Fatalf("creating namespace %s: %v", ns, err)
		}
	}

	ingress := newIngress(apps, "pair", "a.src.com", "a.other.com")
	if err := k8sClient.Create(ctx, ingress); err != nil {
		t.Fatalf("creating ingress: %v", err)
	}

	// The suite runs with GatewaysAvailable false, so asking for it explicitly
	// reproduces a restart before the Gateway API CRDs were registered.
	wanted := true
	policy := &v1alpha1.WildcardCertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "withholding-source"},
		Spec: v1alpha1.WildcardCertificatePolicySpec{
			Zones:                []string{"src.com", "other.com"},
			MaxCertificates:      10,
			Grouping:             v1alpha1.GroupingPerZone,
			Discovery:            &v1alpha1.DiscoverySpec{Gateways: &wanted},
			IssuerRef:            v1alpha1.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: certs,
			KeyVault:             v1alpha1.KeyVaultSpec{Name: "my-vault"},
			OrphanPolicy:         v1alpha1.OrphanPrune,
		},
	}
	if err := k8sClient.Create(ctx, policy); err != nil {
		t.Fatalf("creating policy: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, policy) })

	otherKey := client.ObjectKey{Namespace: certs, Name: "wildcard-other-com"}
	eventually(t, 30*time.Second, func() error {
		var cert cmapi.Certificate
		return k8sClient.Get(ctx, otherKey, &cert)
	})

	// Narrow to one zone, so other.com is orphaned but the plan is not empty --
	// isolating this guard from the empty-plan one.
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current networkingv1.Ingress
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(ingress), &current); err != nil {
			return err
		}
		current.Spec.Rules = []networkingv1.IngressRule{{Host: "a.src.com"}}
		return k8sClient.Update(ctx, &current)
	}); err != nil {
		t.Fatalf("narrowing the ingress: %v", err)
	}

	eventually(t, 30*time.Second, func() error {
		var got v1alpha1.WildcardCertificatePolicy
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &got); err != nil {
			return err
		}
		condition := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionReady)
		if condition == nil || condition.Reason != controller.ReasonPruneWithheld {
			return fmt.Errorf("Ready condition = %+v, want reason %s", condition, controller.ReasonPruneWithheld)
		}
		return nil
	})

	var cert cmapi.Certificate
	if err := k8sClient.Get(ctx, otherKey, &cert); err != nil {
		t.Errorf("pruned against an incomplete discovered set: %v", err)
	}
}

// The inverse of the test above, and the one that matters most.
//
// The withholding guard reads spec.discovery.gateways to tell "the user
// requires this source" from "the user said nothing". That distinction only
// survives if the field is genuinely absent when unset -- and structural
// defaulting would materialise it into every stored object that carries a
// discovery block at all. When that happened, pruning was withheld forever on
// any cluster without Gateway API, which is most of them.
//
// So: a discovery block that does not mention gateways must still prune.
func TestPolicyPrunesWhenDiscoveryOmitsTheUnavailableSource(t *testing.T) {
	requireEnvtest(t)
	ctx := t.Context()
	const apps = "omits-apps"
	const certs = "omits-certs"

	for _, ns := range []string{apps, certs} {
		if err := k8sClient.Create(ctx, newNamespace(ns)); err != nil {
			t.Fatalf("creating namespace %s: %v", ns, err)
		}
	}

	ingress := newIngress(apps, "pair", "a.keep.com", "a.drop.com")
	if err := k8sClient.Create(ctx, ingress); err != nil {
		t.Fatalf("creating ingress: %v", err)
	}

	useIngress := true
	policy := &v1alpha1.WildcardCertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "omitting-source"},
		Spec: v1alpha1.WildcardCertificatePolicySpec{
			Zones:           []string{"keep.com", "drop.com"},
			MaxCertificates: 10,
			Grouping:        v1alpha1.GroupingPerZone,
			// A discovery block that says nothing about gateways. The suite runs
			// with GatewaysAvailable false, so if the field were defaulted to
			// true this policy would never prune again.
			Discovery:            &v1alpha1.DiscoverySpec{Ingress: &useIngress},
			IssuerRef:            v1alpha1.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: certs,
			KeyVault:             v1alpha1.KeyVaultSpec{Name: "my-vault"},
			OrphanPolicy:         v1alpha1.OrphanPrune,
		},
	}
	if err := k8sClient.Create(ctx, policy); err != nil {
		t.Fatalf("creating policy: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, policy) })

	// Guards against the API server quietly reintroducing the default. Read
	// through eventually because k8sClient is the manager's cached client, so a
	// Get straight after a Create races the informer.
	var stored v1alpha1.WildcardCertificatePolicy
	eventually(t, 30*time.Second, func() error {
		return k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &stored)
	})
	if stored.Spec.Discovery.Gateways != nil {
		t.Fatalf("spec.discovery.gateways was materialised as %v; it must stay unset so the "+
			"withholding guard can tell a requirement from a default", *stored.Spec.Discovery.Gateways)
	}

	dropKey := client.ObjectKey{Namespace: certs, Name: "wildcard-drop-com"}
	eventually(t, 30*time.Second, func() error {
		var cert cmapi.Certificate
		return k8sClient.Get(ctx, dropKey, &cert)
	})

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current networkingv1.Ingress
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(ingress), &current); err != nil {
			return err
		}
		current.Spec.Rules = []networkingv1.IngressRule{{Host: "a.keep.com"}}
		return k8sClient.Update(ctx, &current)
	}); err != nil {
		t.Fatalf("narrowing the ingress: %v", err)
	}

	// The prune must actually happen.
	eventually(t, 30*time.Second, func() error {
		var cert cmapi.Certificate
		if err := k8sClient.Get(ctx, dropKey, &cert); err == nil {
			return fmt.Errorf("certificate still present; pruning was withheld when it should not have been")
		} else if !apierrors.IsNotFound(err) {
			return err
		}
		return nil
	})
}

// A platform adopting this operator cannot rename the Key Vault objects its
// Application Gateway listeners already reference -- that is a live cutover --
// so the policy has to write the names it is handed. The plan also has to hold
// the apex without help from discovery: leaving it to an Ingress means deleting
// that Ingress re-issues the same Key Vault object without the apex SAN.
func TestPolicyPinsTheKeyVaultObjectNameAndSeedsTheApex(t *testing.T) {
	requireEnvtest(t)
	ctx := t.Context()
	const certs = "policy-pinned-certs"

	if err := k8sClient.Create(ctx, newNamespace(certs)); err != nil {
		t.Fatalf("creating namespace %s: %v", certs, err)
	}

	policy := &v1alpha1.WildcardCertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "pinned"},
		Spec: v1alpha1.WildcardCertificatePolicySpec{
			Zones:           []string{"pinned.com"},
			MaxCertificates: 10,
			// Grouping is left to its default on purpose: pinning is accepted
			// only under PerZone, and an adopter writes the shape without it.
			IssueZoneWildcards:   true,
			IssueZoneApex:        true,
			IssuerRef:            v1alpha1.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: certs,
			KeyVault:             v1alpha1.KeyVaultSpec{Name: "my-vault"},
			CertificateNames:     map[string]v1alpha1.VaultObjectName{"pinned.com": "ingress-certificate"},
			OrphanPolicy:         v1alpha1.OrphanRetain,
		},
	}
	if err := k8sClient.Create(ctx, policy); err != nil {
		t.Fatalf("creating policy: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, policy) })

	// Nothing in this test routes anything: both SANs come from the seeding.
	certKey := client.ObjectKey{Namespace: certs, Name: "wildcard-pinned-com"}
	eventually(t, 30*time.Second, func() error {
		var cert cmapi.Certificate
		if err := k8sClient.Get(ctx, certKey, &cert); err != nil {
			return err
		}
		want := []string{"*.pinned.com", "pinned.com"}
		got := slices.Clone(cert.Spec.DNSNames)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			return fmt.Errorf("dnsNames = %v, want %v", got, want)
		}
		return nil
	})

	// The sync resource keeps the derived name -- renaming it would orphan the
	// one already generated -- while the vault object follows the pin.
	eventually(t, 30*time.Second, func() error {
		var sync v1alpha1.KeyVaultCertificateSync
		if err := k8sClient.Get(ctx, certKey, &sync); err != nil {
			return err
		}
		if sync.Spec.KeyVault.CertificateName != "ingress-certificate" {
			return fmt.Errorf("certificateName = %q, want ingress-certificate", sync.Spec.KeyVault.CertificateName)
		}
		return nil
	})

	eventually(t, 30*time.Second, func() error {
		var got v1alpha1.WildcardCertificatePolicy
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &got); err != nil {
			return err
		}
		if !meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionReady) {
			return fmt.Errorf("not ready: %+v", got.Status.Conditions)
		}
		if len(got.Status.RequiredCertificates) != 1 {
			return fmt.Errorf("requiredCertificates = %+v, want one", got.Status.RequiredCertificates)
		}
		// The listener is configured from the secret identifier, so that is the
		// field that has to carry the pinned name; the reported certificate name
		// is the cluster-side one and stays derived.
		planned := got.Status.RequiredCertificates[0]
		if planned.Name != "wildcard-pinned-com" {
			return fmt.Errorf("requiredCertificates[0].name = %q, want the derived name", planned.Name)
		}
		want := "https://my-vault.vault.azure.net/secrets/ingress-certificate"
		if planned.SecretIdentifier != want {
			return fmt.Errorf("secretIdentifier = %q, want %q", planned.SecretIdentifier, want)
		}
		return nil
	})
}

// Rejected at admission rather than reported in status. Each of these used to
// be accepted and then quietly not done, which leaves a Ready policy writing a
// Key Vault object no listener reads -- the one failure an adopter cannot see.
func TestPolicyRejectsANameItCannotHonour(t *testing.T) {
	requireEnvtest(t)
	ctx := t.Context()

	base := func() *v1alpha1.WildcardCertificatePolicySpec {
		return &v1alpha1.WildcardCertificatePolicySpec{
			Zones:                []string{"rejected.com"},
			MaxCertificates:      10,
			Grouping:             v1alpha1.GroupingPerZone,
			IssuerRef:            v1alpha1.IssuerReference{Name: "letsencrypt-dns", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: "policy-rejected-certs",
			KeyVault:             v1alpha1.KeyVaultSpec{Name: "my-vault"},
		}
	}

	tests := []struct {
		name   string
		mutate func(*v1alpha1.WildcardCertificatePolicySpec)
	}{
		{
			// The field is real on a KeyVaultCertificateSync, which is how it
			// reached this kind: they share the struct.
			name: "the shared certificateName, which a policy cannot apply",
			mutate: func(spec *v1alpha1.WildcardCertificatePolicySpec) {
				spec.KeyVault.CertificateName = "ingress-certificate"
			},
		},
		{
			// A zone has several certificates under PerWildcard, so a name keyed
			// by zone would name whichever one the operator picked.
			name: "a pin under PerWildcard grouping",
			mutate: func(spec *v1alpha1.WildcardCertificatePolicySpec) {
				spec.Grouping = v1alpha1.GroupingPerWildcard
				spec.CertificateNames = map[string]v1alpha1.VaultObjectName{"rejected.com": "ingress-certificate"}
			},
		},
		{
			// Azure would refuse the import, hours after issuance.
			name: "a pinned name Key Vault would refuse",
			mutate: func(spec *v1alpha1.WildcardCertificatePolicySpec) {
				spec.CertificateNames = map[string]v1alpha1.VaultObjectName{"rejected.com": "9-ingress"}
			},
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := base()
			tc.mutate(spec)
			policy := &v1alpha1.WildcardCertificatePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("rejected-%d", i)},
				Spec:       *spec,
			}
			err := k8sClient.Create(ctx, policy)
			if err == nil {
				_ = k8sClient.Delete(ctx, policy)
				t.Fatal("the API server accepted a policy whose name could never be honoured")
			}
			if !apierrors.IsInvalid(err) {
				t.Fatalf("creating policy: %v, want an Invalid error", err)
			}
		})
	}
}
