package azure_test

import (
	"os"
	"testing"

	"github.com/VileEnd/keyvault_certOperator/internal/infra/azure"
)

func TestNewCredentialRejectsUnknownModes(t *testing.T) {
	if _, err := azure.NewCredential("magic-beans"); err == nil {
		t.Error("expected an error for an unknown credential mode")
	}
}

func TestWorkloadIdentityFailsLoudlyWhenTheWebhookDidNotInject(t *testing.T) {
	// Workload identity is constructed explicitly rather than through the default
	// credential chain precisely so that a broken federation fails here, with a
	// message naming the two things people forget -- the ServiceAccount
	// annotation and the pod label -- instead of surfacing later as an opaque
	// Key Vault authorization error.
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")

	_, err := azure.NewCredential(azure.CredentialWorkloadIdentity)
	if err == nil {
		t.Fatal("expected an error when the workload identity environment is absent")
	}
	for _, want := range []string{"azure.workload.identity/client-id", "azure.workload.identity/use"} {
		if !contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

func TestWorkloadIdentityUsesTheInjectedEnvironment(t *testing.T) {
	// The projected token path must never be hardcoded: it has changed between
	// webhook releases and now embeds a hash of the pod name, so it is always
	// read from AZURE_FEDERATED_TOKEN_FILE.
	tokenFile := t.TempDir() + "/token"
	if err := writeFile(tokenFile, "fake-token"); err != nil {
		t.Fatalf("writing token file: %v", err)
	}
	t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")
	t.Setenv("AZURE_TENANT_ID", "11111111-1111-1111-1111-111111111111")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", tokenFile)

	if _, err := azure.NewCredential(azure.CredentialWorkloadIdentity); err != nil {
		t.Errorf("NewCredential: %v", err)
	}
	// An empty mode must behave as workload identity, so the flag default and
	// the manifest default cannot drift apart.
	if _, err := azure.NewCredential(""); err != nil {
		t.Errorf("NewCredential(\"\"): %v", err)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
