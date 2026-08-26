package controller_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
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
