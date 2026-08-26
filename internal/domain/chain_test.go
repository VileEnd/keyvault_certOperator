package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/VileEnd/keyvault_certOperator/internal/domain"
	"github.com/VileEnd/keyvault_certOperator/internal/testutil"
)

func TestParseBundleKeepsUnrelatedCertificatesRatherThanDroppingThem(t *testing.T) {
	t.Parallel()
	// A Secret can accumulate a stale intermediate after a CA rotation. Silently
	// discarding it would change what reaches Application Gateway without any
	// signal, so anything that does not link into the chain is preserved at the
	// end instead.
	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "test intermediate")
	stranger := testutil.NewRootCA(t, "unrelated authority")

	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com"}})
	certPEM := append(leaf.CertPEM(t), testutil.EncodeCertPEM(t, stranger.Cert)...)

	bundle, err := domain.ParseBundle(certPEM, leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	if len(bundle.Chain) != 2 {
		t.Fatalf("chain = %d certificates, want the intermediate plus the stray one", len(bundle.Chain))
	}
	// The real issuer must still come first: Application Gateway needs the leaf
	// topmost and the chain in issuer order.
	if !bundle.Chain[0].Equal(inter.Cert) {
		t.Error("the issuing intermediate should lead the chain")
	}
	if !bundle.Chain[1].Equal(stranger.Cert) {
		t.Error("the unrelated certificate should be preserved at the end")
	}
}

func TestParseBundleIsStableForAGivenInput(t *testing.T) {
	t.Parallel()
	// An unstable chain order would change the chain digest on every reconcile
	// and mint a new permanent Key Vault version each time.
	root := testutil.NewRootCA(t, "test root")
	inter := root.Intermediate(t, "test intermediate")
	strayA := testutil.NewRootCA(t, "stray a")
	strayB := testutil.NewRootCA(t, "stray b")

	leaf := inter.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com"}})
	certPEM := leaf.CertPEM(t)
	certPEM = append(certPEM, testutil.EncodeCertPEM(t, strayA.Cert)...)
	certPEM = append(certPEM, testutil.EncodeCertPEM(t, strayB.Cert)...)

	first, err := domain.ParseBundle(certPEM, leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	for i := range 10 {
		next, err := domain.ParseBundle(certPEM, leaf.KeyPEM(t, testutil.PKCS8))
		if err != nil {
			t.Fatalf("ParseBundle: %v", err)
		}
		if first.ChainDigest() != next.ChainDigest() {
			t.Fatalf("chain digest changed on iteration %d: %s vs %s",
				i, first.ChainDigest(), next.ChainDigest())
		}
	}
}

func TestParseBundleHandlesALeafOnlySecret(t *testing.T) {
	t.Parallel()
	// Valid input, though Application Gateway wants intermediates too. It must
	// parse rather than fail, so the operator can report the real problem.
	root := testutil.NewRootCA(t, "test root")
	leaf := root.Issue(t, testutil.LeafOptions{DNSNames: []string{"*.x.com"}})

	bundle, err := domain.ParseBundle(leaf.LeafOnlyPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if len(bundle.Chain) != 0 {
		t.Errorf("chain = %d certificates, want none", len(bundle.Chain))
	}
	if bundle.ChainDigest() == "" {
		t.Error("chain digest should still be computed from the leaf alone")
	}
}

func TestBundleAccessors(t *testing.T) {
	t.Parallel()
	root := testutil.NewRootCA(t, "test root")
	notBefore := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)

	leaf := root.Issue(t, testutil.LeafOptions{
		DNSNames:  []string{"*.x.com", "x.com"},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})
	bundle, err := domain.ParseBundle(leaf.CertPEM(t), leaf.KeyPEM(t, testutil.PKCS8))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	if !bundle.NotBefore().Equal(notBefore) {
		t.Errorf("NotBefore() = %s, want %s", bundle.NotBefore(), notBefore)
	}
	if !bundle.NotAfter().Equal(notAfter) {
		t.Errorf("NotAfter() = %s, want %s", bundle.NotAfter(), notAfter)
	}
	// The serial is stamped as a Key Vault tag, so it must be renderable.
	if serial := bundle.SerialHex(); serial == "" || strings.ContainsAny(serial, "ghijklmnopqrstuvwxyz") {
		t.Errorf("SerialHex() = %q, want lowercase hex", serial)
	}
	if got := bundle.DNSNames(); len(got) != 2 {
		t.Errorf("DNSNames() = %v, want both names", got)
	}
	// The hex thumbprint is what lands in status; it must match the raw bytes.
	if len(bundle.ThumbprintHex()) != 40 {
		t.Errorf("ThumbprintHex() = %q, want 40 hex characters for a SHA-1", bundle.ThumbprintHex())
	}
}
