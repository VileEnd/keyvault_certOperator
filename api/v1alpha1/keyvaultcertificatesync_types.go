package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// KeyVaultCertificateSyncSpec describes one certificate to keep in Key Vault.
type KeyVaultCertificateSyncSpec struct {
	// Source selects the certificate to sync.
	// +required
	Source CertificateSourceSpec `json:"source"`

	// KeyVault identifies the destination vault and certificate object.
	// +required
	KeyVault KeyVaultSpec `json:"keyVault"`

	// SyncPolicy tunes resync cadence and archive format.
	// +optional
	SyncPolicy *SyncPolicySpec `json:"syncPolicy,omitempty"`
}

// KeyVaultCertificateSyncStatus reports the observed state of one sync.
type KeyVaultCertificateSyncStatus struct {
	// Conditions holds Ready and Synced.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// CertificateName is the Key Vault object name actually used, whether taken
	// from the spec or derived.
	// +optional
	CertificateName string `json:"certificateName,omitempty"`

	// SecretIdentifier is the *versionless* Key Vault secret URI to configure on
	// the Application Gateway listener.
	//
	// It is versionless on purpose. Application Gateway polls this URI roughly
	// every four hours and rotates to any newer version it finds; a versioned URI
	// pins the listener to one version and silently disables that rotation.
	// +optional
	SecretIdentifier string `json:"secretIdentifier,omitempty"`

	// VaultCertificateVersion is the version created by the most recent import.
	// +optional
	VaultCertificateVersion string `json:"vaultCertificateVersion,omitempty"`

	// LastSyncedThumbprint is the SHA-1 of the leaf, matching Key Vault's x5t.
	// +optional
	LastSyncedThumbprint string `json:"lastSyncedThumbprint,omitempty"`

	// ChainDigest covers the leaf and its full chain. The thumbprint alone
	// cannot detect a CA rotating its intermediates, which leaves the leaf
	// byte-identical while the stored chain goes stale.
	// +optional
	ChainDigest string `json:"chainDigest,omitempty"`

	// NotAfter is the leaf's expiry.
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`

	// DNSNames are the subject alternative names on the synced certificate.
	// +optional
	// +kubebuilder:validation:MaxItems=100
	DNSNames []string `json:"dnsNames,omitempty"`

	// LastSyncTime is when the sync last completed successfully.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=kvcs,categories=certsync
// +kubebuilder:printcolumn:name="Vault Certificate",type=string,JSONPath=`.status.certificateName`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Not After",type=date,JSONPath=`.status.notAfter`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// KeyVaultCertificateSync keeps one Kubernetes TLS Secret mirrored into one
// Azure Key Vault certificate, so an Application Gateway listener can serve it.
//
// Deleting this resource does not delete the Key Vault certificate. Application
// Gateway may still be serving it, and removing it would disable the listener.
type KeyVaultCertificateSync struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec KeyVaultCertificateSyncSpec `json:"spec"`
	// +optional
	Status KeyVaultCertificateSyncStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeyVaultCertificateSyncList contains a list of KeyVaultCertificateSync.
type KeyVaultCertificateSyncList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeyVaultCertificateSync `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &KeyVaultCertificateSync{}, &KeyVaultCertificateSyncList{})
		return nil
	})
}
