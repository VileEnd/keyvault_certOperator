package azure

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// CredentialMode selects how the operator authenticates to Azure.
type CredentialMode string

const (
	// CredentialWorkloadIdentity uses the AKS OIDC issuer federated to a managed
	// identity. This is the production mode and the default: nothing long-lived
	// is stored in the cluster, and there is no credential to rotate.
	//
	// It requires both the ServiceAccount annotation
	// azure.workload.identity/client-id and the pod label
	// azure.workload.identity/use: "true". Without the label the mutating webhook
	// skips the pod and it fails on the next restart.
	CredentialWorkloadIdentity CredentialMode = "workload-identity"
	// CredentialDefault uses the full DefaultAzureCredential chain. Intended for
	// local development against a real vault, where an az-CLI login is the only
	// practical option. Not for in-cluster use.
	CredentialDefault CredentialMode = "default"
)

// NewCredential builds the token credential for the given mode.
//
// Workload identity is constructed explicitly rather than through
// DefaultAzureCredential so that a missing or misconfigured federation fails
// immediately and unambiguously, instead of silently falling through the chain
// and surfacing later as an authorization error against Key Vault.
func NewCredential(mode CredentialMode) (azcore.TokenCredential, error) {
	switch mode {
	case "", CredentialWorkloadIdentity:
		// Client ID, tenant ID and the projected token path all default from the
		// environment variables injected by the workload identity webhook. The
		// token path in particular must never be hardcoded: it has changed
		// between webhook releases and now embeds a hash of the pod name.
		cred, err := azidentity.NewWorkloadIdentityCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("configuring Azure workload identity "+
				"(check the ServiceAccount's azure.workload.identity/client-id annotation and "+
				"the pod's azure.workload.identity/use label): %w", err)
		}
		return cred, nil
	case CredentialDefault:
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("configuring the default Azure credential chain: %w", err)
		}
		return cred, nil
	default:
		return nil, fmt.Errorf("unknown Azure credential mode %q", mode)
	}
}
