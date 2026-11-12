package main

import (
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/VileEnd/keyvault_certOperator/internal/infra/azure"
)

func TestParseAllowedVaultsResolvesAgainstTheOperatorsCloud(t *testing.T) {
	t.Parallel()
	// A bare name in --allowed-vaults has to resolve to the same URL the
	// controllers derive for a resource naming that vault. Resolving it against
	// a hardcoded public cloud produced an entry nothing could ever match, and
	// ErrVaultNotAllowed is deliberately not retryable -- so on a sovereign
	// cloud every certificate failed permanently.
	tests := []struct {
		name  string
		cloud azure.Cloud
		want  string
	}{
		{name: "public", cloud: azure.CloudPublic, want: "https://kvname.vault.azure.net"},
		{name: "government", cloud: azure.CloudUSGovernment, want: "https://kvname.vault.usgovcloudapi.net"},
		{name: "china", cloud: azure.CloudChina, want: "https://kvname.vault.azure.cn"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allowed, err := parseAllowedVaults("kvname", tc.cloud)
			if err != nil {
				t.Fatalf("parseAllowedVaults: %v", err)
			}
			if !allowed.Permits(tc.want) {
				t.Errorf("allowlist %s does not permit %q", allowed, tc.want)
			}
			// And it must still be an allowlist, not a pass-through.
			if allowed.Permits("https://other.vault.azure.net") {
				t.Errorf("allowlist %s permits a vault it never named", allowed)
			}
		})
	}
}

func TestParseAllowedVaultsRejectsWhatIsNotAVault(t *testing.T) {
	t.Parallel()
	for _, entry := range []string{"https://attacker.example.com", "no", "bad--name"} {
		if _, err := parseAllowedVaults(entry, azure.CloudPublic); err == nil {
			t.Errorf("parseAllowedVaults(%q) succeeded; want an error at startup", entry)
		}
	}
}

func TestParseAllowedVaultsEmptyMeansUnrestricted(t *testing.T) {
	t.Parallel()
	allowed, err := parseAllowedVaults("  ,  ", azure.CloudPublic)
	if err != nil {
		t.Fatalf("parseAllowedVaults: %v", err)
	}
	if allowed.Enforced() {
		t.Errorf("allowlist %s is enforced; blank entries must not bound anything", allowed)
	}
}

// switchableMapper serves no kind until it is told to, the way the API server
// does before and after a CRD is installed. The stock mapper is not safe to
// change while it is being read, which the race detector rightly objects to.
type switchableMapper struct {
	meta.RESTMapper
	served atomic.Bool
}

func (m *switchableMapper) RESTMapping(gk schema.GroupKind, _ ...string) (*meta.RESTMapping, error) {
	if !m.served.Load() {
		return nil, &meta.NoKindMatchError{GroupKind: gk}
	}
	return &meta.RESTMapping{}, nil
}

func TestCRDWatcherRestartsOnceTheKindIsServed(t *testing.T) {
	t.Parallel()
	// Gateway API installed after the operator started is otherwise invisible
	// until someone restarts the pod by hand.
	gk := schema.GroupKind{Group: "gateway.networking.k8s.io", Kind: "Gateway"}
	mapper := &switchableMapper{}
	restarted := make(chan struct{})

	watcher := &crdWatcher{
		mapper:   mapper,
		kinds:    []schema.GroupKind{gk},
		version:  "v1",
		interval: 10 * time.Millisecond,
		restart:  func() { close(restarted) },
	}
	go func() { _ = watcher.Start(t.Context()) }()

	select {
	case <-restarted:
		t.Fatal("restarted while the kind was still absent")
	case <-time.After(50 * time.Millisecond):
	}

	mapper.served.Store(true)

	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("did not restart after the kind appeared")
	}
}
