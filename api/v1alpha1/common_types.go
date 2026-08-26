package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Condition types shared by both kinds.
const (
	// ConditionReady summarises whether the resource is doing its job.
	ConditionReady = "Ready"
	// ConditionSynced reports whether Key Vault holds the desired certificate.
	ConditionSynced = "Synced"
	// ConditionDiscovered reports whether a discovery pass completed.
	ConditionDiscovered = "Discovered"
	// ConditionCertManagerAvailable reports whether cert-manager's Certificate
	// CRD is installed. Its absence degrades the policy controller loudly rather
	// than failing it: the required certificates are still reported.
	ConditionCertManagerAvailable = "CertManagerAvailable"
)

// PKCS12Profile selects the algorithm set used to build the PFX sent to Key Vault.
//
// This is a compatibility knob, not a security one. Key Vault discards the
// password and re-encodes the certificate on import, so the archive exists only
// in memory for the duration of one call and Application Gateway ultimately
// reads Key Vault's own output.
// +kubebuilder:validation:Enum=legacy;passwordless;modern
type PKCS12Profile string

const (
	// PKCS12Legacy uses 3DES with SHA-1, the profile Azure's Application Gateway
	// troubleshooting guidance asks for by name. This is the default because
	// some Azure services cannot parse AES-256-CBC archives.
	PKCS12Legacy PKCS12Profile = "legacy"
	// PKCS12Passwordless produces an unencrypted archive; Key Vault's import API
	// documents the password as optional.
	PKCS12Passwordless PKCS12Profile = "passwordless"
	// PKCS12Modern uses PBES2 with AES-256-CBC. Verify against a real
	// Application Gateway before adopting it.
	PKCS12Modern PKCS12Profile = "modern"
)

// LocalSecretReference names a Secret in the same namespace as the referring
// resource. Cross-namespace references are deliberately not offered: they would
// let a resource in one namespace read TLS private keys from another.
type LocalSecretReference struct {
	// Name is the Secret's name. It must be of type kubernetes.io/tls.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// CertificateSourceSpec selects where the certificate is read from.
type CertificateSourceSpec struct {
	// SecretRef names the kubernetes.io/tls Secret holding tls.crt and tls.key.
	// +required
	SecretRef LocalSecretReference `json:"secretRef"`
}

// KeyVaultSpec identifies the target vault and certificate object.
// +kubebuilder:validation:XValidation:rule="has(self.name) != has(self.vaultURL)",message="exactly one of name or vaultURL must be set"
type KeyVaultSpec struct {
	// Name is the Key Vault's short name, resolved against Cloud. Mutually
	// exclusive with VaultURL.
	// +optional
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=24
	Name string `json:"name,omitempty"`

	// VaultURL is the vault's full base URL. Use this for sovereign clouds or a
	// private endpoint. Mutually exclusive with Name.
	// +optional
	// +kubebuilder:validation:Pattern=`^https://.+$`
	VaultURL string `json:"vaultURL,omitempty"`

	// Cloud selects the Azure environment when Name is used.
	// +optional
	// +kubebuilder:validation:Enum=AzurePublicCloud;AzureUSGovernmentCloud;AzureChinaCloud
	// +kubebuilder:default=AzurePublicCloud
	Cloud string `json:"cloud,omitempty"`

	// CertificateName is the Key Vault object name. Defaults to a value derived
	// from the certificate's subject alternative names.
	//
	// The derivation replaces dots with hyphens, which is not reversible: both
	// "foo.example.com" and "foo-example.com" derive "foo-example-com". Set this
	// explicitly when that matters -- an Application Gateway listener references
	// the name, so a silent change would be an outage.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-zA-Z][a-zA-Z0-9-]{0,126}$`
	CertificateName string `json:"certificateName,omitempty"`
}

// SyncPolicySpec tunes how a certificate is pushed to Key Vault.
type SyncPolicySpec struct {
	// ResyncInterval is how often to re-check Key Vault even without a change in
	// the cluster, catching drift applied out of band. Defaults to one hour.
	// +optional
	// +kubebuilder:default="1h"
	ResyncInterval *metav1.Duration `json:"resyncInterval,omitempty"`

	// PKCS12Profile selects the archive format sent to Key Vault.
	// +optional
	// +kubebuilder:default=legacy
	PKCS12Profile PKCS12Profile `json:"pkcs12Profile,omitempty"`
}
