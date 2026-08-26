//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/test/e2e/fakekeyvault"
)

// requireCertManager skips unless a running cert-manager is present. The suite
// asserts on certificates it actually issues, so a missing cert-manager must
// skip rather than quietly assert nothing.
func requireCertManager(t *testing.T, c client.Client) {
	t.Helper()
	if os.Getenv("E2E_CERT_MANAGER") != "1" {
		t.Skip("E2E_CERT_MANAGER is not 1; run 'make e2e-fullstack' to install cert-manager and enable this")
	}
	var deployment appsv1.Deployment
	key := client.ObjectKey{Namespace: "cert-manager", Name: "cert-manager"}
	if err := c.Get(t.Context(), key, &deployment); err != nil {
		t.Fatalf("cert-manager is expected but not installed: %v", err)
	}
	if deployment.Status.AvailableReplicas == 0 {
		t.Fatalf("cert-manager is installed but has no available replicas")
	}
}

// TestCertManagerIssuesAndTheOperatorSyncsItToKeyVault exercises the whole
// pipeline rather than any single hop:
//
//	Ingress hostnames
//	  -> the policy plans a covering wildcard
//	  -> the operator creates a cert-manager Certificate
//	  -> cert-manager actually issues it and writes a Secret
//	  -> the Secret carries the managed label, so it is inside the operator's
//	     label-scoped cache
//	  -> the operator parses it and imports it into Key Vault
//
// Every earlier test stops at one of those arrows. In particular the other
// end-to-end test hand-writes the Secret, so nothing before it is proven. Here
// nobody creates the Secret: cert-manager does, from the Certificate the
// operator itself asked for.
func TestCertManagerIssuesAndTheOperatorSyncsItToKeyVault(t *testing.T) {
	h := setup(t)
	requireCertManager(t, h.client)
	ctx := t.Context()

	const zone = "fullstack.example"
	const certName = "wildcard-fullstack-example"

	h.mustCreate(t, &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "fullstack", Namespace: appNamespace},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{
			{Host: "api." + zone},
			{Host: "web." + zone},
			{Host: zone},
		}},
	})

	policy := &v1alpha1.WildcardCertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-fullstack"},
		Spec: v1alpha1.WildcardCertificatePolicySpec{
			Zones:           []string{zone},
			MaxCertificates: 5,
			Grouping:        v1alpha1.GroupingPerZone,
			// The CA issuer the harness created. Production uses ACME with a
			// DNS-01 solver, since wildcards require it; what matters here is
			// everything downstream of issuance.
			IssuerRef:            v1alpha1.IssuerReference{Name: "e2e-ca-issuer", Kind: "ClusterIssuer", Group: "cert-manager.io"},
			CertificateNamespace: certNamespace,
			KeyVault:             v1alpha1.KeyVaultSpec{VaultURL: h.vault.URL()},
		},
	}
	h.mustCreate(t, policy)
	t.Cleanup(func() { _ = h.client.Delete(ctx, policy) })

	certKey := client.ObjectKey{Namespace: certNamespace, Name: certName}

	// 1. The operator asks for the certificate.
	eventually(t, 90*time.Second, func() error {
		var cert cmapi.Certificate
		if err := h.client.Get(ctx, certKey, &cert); err != nil {
			return err
		}
		want := []string{"*." + zone, zone}
		got := slices.Clone(cert.Spec.DNSNames)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			return fmt.Errorf("dnsNames = %v, want %v", got, want)
		}
		return nil
	})

	// 2. cert-manager genuinely issues it.
	eventually(t, 180*time.Second, func() error {
		var cert cmapi.Certificate
		if err := h.client.Get(ctx, certKey, &cert); err != nil {
			return err
		}
		for _, condition := range cert.Status.Conditions {
			if condition.Type == cmapi.CertificateConditionReady {
				if condition.Status == cmmeta.ConditionTrue {
					return nil
				}
				return fmt.Errorf("certificate not ready: %s: %s", condition.Reason, condition.Message)
			}
		}
		return fmt.Errorf("certificate has no Ready condition yet")
	})

	// 3. The issued Secret carries the managed label. Without it the Secret would
	//    fall outside the operator's label-scoped cache and never be seen -- the
	//    single most easily-broken link in this chain.
	var issued corev1.Secret
	eventually(t, 60*time.Second, func() error {
		key := client.ObjectKey{Namespace: certNamespace, Name: certName + "-tls"}
		if err := h.client.Get(ctx, key, &issued); err != nil {
			return err
		}
		if issued.Type != corev1.SecretTypeTLS {
			return fmt.Errorf("secret type = %q", issued.Type)
		}
		if issued.Labels[v1alpha1.LabelManaged] != v1alpha1.LabelManagedValue {
			return fmt.Errorf("secret labels = %v, want the managed label", issued.Labels)
		}
		if len(issued.Data[corev1.TLSCertKey]) == 0 {
			return fmt.Errorf("secret has no certificate data")
		}
		return nil
	})

	// 4. The operator syncs it into Key Vault.
	syncKey := client.ObjectKey{Namespace: certNamespace, Name: certName}
	eventually(t, 120*time.Second, func() error {
		var sync v1alpha1.KeyVaultCertificateSync
		if err := h.client.Get(ctx, syncKey, &sync); err != nil {
			return err
		}
		condition := meta.FindStatusCondition(sync.Status.Conditions, v1alpha1.ConditionReady)
		if condition == nil || condition.Status != metav1.ConditionTrue {
			return fmt.Errorf("sync not ready: %+v", condition)
		}
		return nil
	})

	// 5. What actually arrived at Key Vault is the certificate cert-manager
	//    issued, complete and in the right format.
	imports := h.vault.Imports()
	idx := slices.IndexFunc(imports, func(i fakekeyvault.Import) bool { return i.Name == certName })
	if idx < 0 {
		t.Fatalf("Key Vault received no import for %q; imports = %d", certName, len(imports))
	}
	got := imports[idx]

	if got.ContentType != app.ContentTypePKCS12 {
		t.Errorf("content type = %q, want %q", got.ContentType, app.ContentTypePKCS12)
	}
	if !slices.Contains(got.Leaf.DNSNames, "*."+zone) {
		t.Errorf("uploaded leaf SANs = %v, want the wildcard %q", got.Leaf.DNSNames, "*."+zone)
	}
	if !slices.Contains(got.Leaf.DNSNames, zone) {
		t.Errorf("uploaded leaf SANs = %v, want the apex %q", got.Leaf.DNSNames, zone)
	}
	// The intermediate that signed the leaf must travel with it. Application
	// Gateway names an incomplete chain as a leading cause of certificate
	// failures, so a leaf-only upload would be a real defect.
	if len(got.Chain) == 0 {
		t.Fatal("uploaded archive has no issuing chain; Application Gateway requires the intermediates")
	}
	if !got.Chain[0].IsCA {
		t.Errorf("first chain entry %q is not a CA certificate", got.Chain[0].Subject.CommonName)
	}
	// The leaf has to come first and the chain must actually chain to it.
	if got.Leaf.Issuer.CommonName != got.Chain[0].Subject.CommonName {
		t.Errorf("leaf issuer %q does not match the first chain entry %q",
			got.Leaf.Issuer.CommonName, got.Chain[0].Subject.CommonName)
	}
	if got.Tags[app.TagChainDigest] == "" {
		t.Error("the chain digest tag is missing")
	}
	if h.vault.TokenGrants() == 0 {
		t.Error("no access token was issued; the request bypassed authentication")
	}

	// 6. Steady state: cert-manager is not renewing, so no further imports.
	consistently(t, 8*time.Second, func() error {
		if n := h.vault.ImportCount(certName); n != 1 {
			return fmt.Errorf("imports = %d, want it to stay at 1", n)
		}
		return nil
	})
}
