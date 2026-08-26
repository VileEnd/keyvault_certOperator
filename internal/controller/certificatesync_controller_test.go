package controller_test

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"
	"github.com/VileEnd/keyvault_certOperator/internal/testutil"
)

func TestSyncControllerImportsOnceAndThenLeavesKeyVaultAlone(t *testing.T) {
	ctx := t.Context()
	const namespace = "sync-steady-state"
	const certName = "wildcard-steady-com"

	if err := k8sClient.Create(ctx, newNamespace(namespace)); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}

	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "test intermediate")
	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.steady.com", "steady.com"}})

	secret := newTLSSecret(t, namespace, "steady-tls", leaf)
	if err := k8sClient.Create(ctx, secret); err != nil {
		t.Fatalf("creating secret: %v", err)
	}

	sync := &v1alpha1.KeyVaultCertificateSync{
		ObjectMeta: metav1.ObjectMeta{Name: "steady", Namespace: namespace},
		Spec: v1alpha1.KeyVaultCertificateSyncSpec{
			Source:   v1alpha1.CertificateSourceSpec{SecretRef: v1alpha1.LocalSecretReference{Name: "steady-tls"}},
			KeyVault: v1alpha1.KeyVaultSpec{Name: "my-vault", CertificateName: certName},
		},
	}
	if err := k8sClient.Create(ctx, sync); err != nil {
		t.Fatalf("creating sync: %v", err)
	}

	key := client.ObjectKeyFromObject(sync)
	eventually(t, 30*time.Second, func() error {
		var got v1alpha1.KeyVaultCertificateSync
		if err := k8sClient.Get(ctx, key, &got); err != nil {
			return err
		}
		if !meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionReady) {
			return fmt.Errorf("not ready yet: %+v", got.Status.Conditions)
		}
		// Application Gateway must be pointed at a versionless URI, or automatic
		// rotation never happens.
		want := "https://my-vault.vault.azure.net/secrets/" + certName
		if got.Status.SecretIdentifier != want {
			return fmt.Errorf("secret identifier = %q, want %q", got.Status.SecretIdentifier, want)
		}
		if got.Status.LastSyncedThumbprint == "" {
			return fmt.Errorf("thumbprint not recorded")
		}
		return nil
	})

	if count := testVault.importCount(certName); count != 1 {
		t.Fatalf("imports = %d after the first sync, want 1", count)
	}

	// The steady state is the point. Every import mints a permanent Key Vault
	// version and is a candidate Application Gateway rotation, so a running
	// operator over an unchanged certificate must issue none at all -- including
	// across the Secret updates that a busy cluster produces.
	for i := range 3 {
		// The controller writes status concurrently, so a plain update races it.
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var current v1alpha1.KeyVaultCertificateSync
			if err := k8sClient.Get(ctx, key, &current); err != nil {
				return err
			}
			if current.Annotations == nil {
				current.Annotations = map[string]string{}
			}
			current.Annotations["test.certsync/nudge"] = fmt.Sprint(i)
			return k8sClient.Update(ctx, &current)
		}); err != nil {
			t.Fatalf("nudging sync: %v", err)
		}
	}

	consistently(t, 3*time.Second, func() error {
		if count := testVault.importCount(certName); count != 1 {
			return fmt.Errorf("imports = %d, want it to stay at 1", count)
		}
		return nil
	})
}

func TestSyncControllerImportsAgainWhenTheCertificateIsRenewed(t *testing.T) {
	ctx := t.Context()
	const namespace = "sync-renewal"
	const certName = "wildcard-renewal-com"

	if err := k8sClient.Create(ctx, newNamespace(namespace)); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}

	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "test intermediate")
	original := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.renewal.com"}})

	secret := newTLSSecret(t, namespace, "renewal-tls", original)
	if err := k8sClient.Create(ctx, secret); err != nil {
		t.Fatalf("creating secret: %v", err)
	}

	sync := &v1alpha1.KeyVaultCertificateSync{
		ObjectMeta: metav1.ObjectMeta{Name: "renewal", Namespace: namespace},
		Spec: v1alpha1.KeyVaultCertificateSyncSpec{
			Source:   v1alpha1.CertificateSourceSpec{SecretRef: v1alpha1.LocalSecretReference{Name: "renewal-tls"}},
			KeyVault: v1alpha1.KeyVaultSpec{Name: "my-vault", CertificateName: certName},
		},
	}
	if err := k8sClient.Create(ctx, sync); err != nil {
		t.Fatalf("creating sync: %v", err)
	}

	eventually(t, 30*time.Second, func() error {
		if count := testVault.importCount(certName); count != 1 {
			return fmt.Errorf("imports = %d, want 1", count)
		}
		return nil
	})

	// cert-manager renews by rewriting the same Secret. The field index on the
	// referenced Secret name is what turns that write into a reconcile within
	// seconds rather than at the next hourly resync.
	renewed := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.renewal.com"}})
	var current corev1.Secret
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "renewal-tls"}, &current); err != nil {
		t.Fatalf("re-reading secret: %v", err)
	}
	current.Data["tls.crt"] = renewed.CertPEM(t)
	current.Data["tls.key"] = renewed.KeyPEM(t, testutil.PKCS8)
	if err := k8sClient.Update(ctx, &current); err != nil {
		t.Fatalf("updating secret: %v", err)
	}

	eventually(t, 30*time.Second, func() error {
		if count := testVault.importCount(certName); count != 2 {
			return fmt.Errorf("imports = %d, want 2 after renewal", count)
		}
		return nil
	})
}

func TestSyncControllerReportsAnInvalidSourceWithoutRetryingForever(t *testing.T) {
	ctx := t.Context()
	const namespace = "sync-invalid"

	if err := k8sClient.Create(ctx, newNamespace(namespace)); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}

	root := testutil.NewRootCA(t, "test root")
	now := time.Now()
	expired := root.Issue(t, testutil.LeafOptions{
		DNSNames:  []string{"*.expired.com"},
		NotBefore: now.Add(-48 * time.Hour),
		NotAfter:  now.Add(-time.Hour),
	})

	if err := k8sClient.Create(ctx, newTLSSecret(t, namespace, "expired-tls", expired)); err != nil {
		t.Fatalf("creating secret: %v", err)
	}

	sync := &v1alpha1.KeyVaultCertificateSync{
		ObjectMeta: metav1.ObjectMeta{Name: "expired", Namespace: namespace},
		Spec: v1alpha1.KeyVaultCertificateSyncSpec{
			Source:   v1alpha1.CertificateSourceSpec{SecretRef: v1alpha1.LocalSecretReference{Name: "expired-tls"}},
			KeyVault: v1alpha1.KeyVaultSpec{Name: "my-vault", CertificateName: "wildcard-expired-com"},
		},
	}
	if err := k8sClient.Create(ctx, sync); err != nil {
		t.Fatalf("creating sync: %v", err)
	}

	// Key Vault rejects expired certificates with an opaque 400, so this is
	// caught locally and surfaced as a condition a user can act on.
	eventually(t, 30*time.Second, func() error {
		var got v1alpha1.KeyVaultCertificateSync
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(sync), &got); err != nil {
			return err
		}
		condition := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionReady)
		if condition == nil || condition.Status != metav1.ConditionFalse {
			return fmt.Errorf("Ready condition = %+v, want False", condition)
		}
		if condition.Reason != "CertificateExpired" {
			return fmt.Errorf("reason = %q, want CertificateExpired", condition.Reason)
		}
		return nil
	})

	if count := testVault.importCount("wildcard-expired-com"); count != 0 {
		t.Errorf("imports = %d, want 0 -- an expired certificate must never reach Azure", count)
	}
}

func TestSyncControllerWaitsForACertificateThatDoesNotExistYet(t *testing.T) {
	ctx := t.Context()
	const namespace = "sync-pending"
	const certName = "wildcard-pending-com"

	if err := k8sClient.Create(ctx, newNamespace(namespace)); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}

	// A policy creates the sync resource alongside the cert-manager Certificate,
	// so this ordering is the normal case rather than an edge case: the sync
	// necessarily exists before cert-manager has issued anything.
	sync := &v1alpha1.KeyVaultCertificateSync{
		ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: namespace},
		Spec: v1alpha1.KeyVaultCertificateSyncSpec{
			Source:   v1alpha1.CertificateSourceSpec{SecretRef: v1alpha1.LocalSecretReference{Name: "pending-tls"}},
			KeyVault: v1alpha1.KeyVaultSpec{Name: "my-vault", CertificateName: certName},
		},
	}
	if err := k8sClient.Create(ctx, sync); err != nil {
		t.Fatalf("creating sync: %v", err)
	}

	eventually(t, 30*time.Second, func() error {
		var got v1alpha1.KeyVaultCertificateSync
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(sync), &got); err != nil {
			return err
		}
		condition := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionReady)
		if condition == nil || condition.Status != metav1.ConditionFalse {
			return fmt.Errorf("Ready = %+v, want False", condition)
		}
		// Reported as "waiting", not as a failure, so a normal startup ordering
		// does not look like a broken operator.
		if condition.Reason != "SourceNotFound" {
			return fmt.Errorf("reason = %q, want SourceNotFound", condition.Reason)
		}
		return nil
	})

	// The Secret watch must pick it up as soon as cert-manager writes it.
	root := testutil.NewRootCA(t, "test root")
	leaf := root.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.pending.com"}})
	if err := k8sClient.Create(ctx, newTLSSecret(t, namespace, "pending-tls", leaf)); err != nil {
		t.Fatalf("creating secret: %v", err)
	}

	eventually(t, 30*time.Second, func() error {
		var got v1alpha1.KeyVaultCertificateSync
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(sync), &got); err != nil {
			return err
		}
		if !meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionReady) {
			return fmt.Errorf("not ready: %+v", got.Status.Conditions)
		}
		return nil
	})

	if count := testVault.importCount(certName); count != 1 {
		t.Errorf("imports = %d, want 1", count)
	}
}
