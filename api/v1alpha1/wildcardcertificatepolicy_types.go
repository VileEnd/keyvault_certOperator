package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CertificateGrouping selects how discovered hostnames are packed into certificates.
// +kubebuilder:validation:Enum=PerZone;PerWildcard
type CertificateGrouping string

const (
	// GroupingPerZone issues one SAN certificate per zone. This is the default
	// and keeps the Application Gateway listener, site and certificate counts as
	// low as possible -- all three share a hard, non-adjustable ceiling of 100.
	//
	// The certificate is named after a SAN it actually carries, which is
	// "wildcard-<zone>" whenever the zone's own wildcard is covered. Where it
	// is not -- a cluster routing only "a.b.x.com" needs "*.b.x.com", not
	// "*.x.com" -- the name follows the SAN instead, because a listener
	// configured against "wildcard-x-com" would otherwise be handed a
	// certificate that matches nothing it serves. Set issueZoneWildcards to
	// pin the name, since the zone wildcard is then always covered.
	GroupingPerZone CertificateGrouping = "PerZone"
	// GroupingPerWildcard issues one certificate per distinct wildcard.
	GroupingPerWildcard CertificateGrouping = "PerWildcard"
)

// OrphanPolicy decides what happens to a certificate that discovery no longer
// requires.
// +kubebuilder:validation:Enum=Retain;Prune
type OrphanPolicy string

const (
	// OrphanRetain leaves orphaned certificates in place and only reports them.
	// This is the default because an Application Gateway listener may still be
	// serving the certificate, and removing it would disable that listener.
	OrphanRetain OrphanPolicy = "Retain"
	// OrphanPrune deletes the cert-manager Certificate and the sync resource.
	// The Key Vault certificate itself is never deleted under either policy.
	OrphanPrune OrphanPolicy = "Prune"
)

// IssuerReference points at the cert-manager issuer that performs DNS-01.
//
// The issuer is referenced, never created: it holds ACME account details and
// solver configuration that belong to the cluster operator, not to us.
type IssuerReference struct {
	// Name of the issuer.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Kind of the issuer.
	// +optional
	// +kubebuilder:validation:Enum=Issuer;ClusterIssuer
	// +kubebuilder:default=ClusterIssuer
	Kind string `json:"kind,omitempty"`

	// Group of the issuer.
	// +optional
	// +kubebuilder:default=cert-manager.io
	Group string `json:"group,omitempty"`
}

// DiscoverySpec selects where hostnames are discovered from.
type DiscoverySpec struct {
	// Ingress enables discovery from networking.k8s.io Ingress resources.
	//
	// Unset means "use this source when it is available", which is the default
	// behaviour. It is deliberately left unset rather than defaulted to true:
	// structural defaulting would materialise the value into every stored
	// object, erasing the difference between a source the user required and one
	// they never mentioned.
	// +optional
	Ingress *bool `json:"ingress,omitempty"`

	// HTTPRoutes enables discovery from Gateway API HTTPRoute resources.
	//
	// The watch can only be established if the Gateway API CRDs are present when
	// the operator starts, so installing Gateway API later requires a restart.
	//
	// Unset means "use it when available". Setting it explicitly to true states
	// a requirement: pruning is then withheld if the CRDs were absent at
	// startup, because the discovered set would be incomplete.
	// +optional
	HTTPRoutes *bool `json:"httpRoutes,omitempty"`

	// Gateways enables discovery from the hostnames declared on Gateway API
	// Gateway listeners.
	//
	// This is not redundant with HTTPRoutes. A route whose spec.hostnames is
	// empty inherits the hostnames its listener allows, so with a wildcard
	// listener -- the common shape behind Envoy Gateway -- the hostname exists
	// only on the Gateway and reading routes alone would discover nothing.
	//
	// Listener protocol is deliberately ignored. A listener may terminate plain
	// HTTP because TLS is already terminated upstream at Application Gateway,
	// which is exactly the topology this operator serves; the hostname is still
	// a hostname the cluster routes.
	//
	// Unset means "use it when available". Setting it explicitly to true states
	// a requirement: pruning is then withheld if the CRDs were absent at
	// startup, because the discovered set would be incomplete.
	// +optional
	Gateways *bool `json:"gateways,omitempty"`

	// NamespaceSelector narrows discovery to matching namespaces. Empty means
	// all namespaces.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// VaultObjectName is a Key Vault object name: 1-127 characters of letters,
// digits and hyphens, starting with a letter. It mirrors
// domain.ValidateVaultCertificateName, so a name the API server accepts is one
// Azure accepts.
// +kubebuilder:validation:Pattern=`^[a-zA-Z][a-zA-Z0-9-]{0,126}$`
// +kubebuilder:validation:MaxLength=127
type VaultObjectName string

// WildcardCertificatePolicySpec describes which wildcards the cluster needs.
//
// The first validation rule below closes a trap rather than adding a feature.
// keyVault is the same struct a KeyVaultCertificateSync uses, so its
// certificateName was accepted here and then discarded -- a policy plans one
// certificate per zone, and one name cannot apply to all of them. The discard
// was silent, which is the worst shape it could take: a green, Ready policy
// writing a Key Vault object no Application Gateway listener reads. A degraded
// condition would still leave a window in which that object is written, so the
// field is refused outright and the message names certificateNames instead. The
// cost is that a policy already stored with it set has to drop it before it can
// be updated again; validation ratcheting (Kubernetes 1.30+) limits that to
// updates which touch the spec.
// +kubebuilder:validation:XValidation:rule="!has(self.keyVault.certificateName)",message="spec.keyVault.certificateName is ignored by a policy, which plans one certificate per zone; pin the Key Vault object name per zone with spec.certificateNames"
// +kubebuilder:validation:XValidation:rule="!has(self.certificateNames) || (has(self.grouping) && self.grouping == 'PerZone')",message="spec.certificateNames requires grouping: PerZone, the only grouping where a zone has exactly one certificate to name"
type WildcardCertificatePolicySpec struct {
	// Zones is the allowlist of DNS zones issuance may happen inside. It is
	// required and has no permissive default.
	//
	// This is the primary safety boundary. Discovery reacts to Ingress and
	// HTTPRoute resources, so without an allowlist anyone able to create one
	// could trigger ACME issuance and spend the cluster's Let's Encrypt rate
	// limit for a registered domain. Zones at or above a public suffix are
	// rejected, so "*.com" is unreachable by construction.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=50
	Zones []string `json:"zones"`

	// IssueZoneWildcards issues "*.<zone>" for every zone in Zones, whether or
	// not anything in the cluster routes a name under it.
	//
	// Discovery answers "what does the cluster route today", which is empty
	// before the first workload exists -- and an Application Gateway listener
	// cannot reference a Key Vault certificate that does not exist yet, so a
	// new zone is otherwise a chicken-and-egg problem. Set this when the
	// gateway must serve a zone's wildcard regardless of what is deployed
	// behind it.
	//
	// The seeded names pass the same zone allowlist, public-suffix check and
	// certificate cap as a discovered one.
	// +optional
	// +kubebuilder:default=false
	IssueZoneWildcards bool `json:"issueZoneWildcards,omitempty"`

	// IssueZoneApex covers the bare zone -- "x.com" as well as "*.x.com" -- for
	// every zone in Zones.
	//
	// A wildcard matches exactly one label, so it does not cover its own apex.
	// Without this the apex is a SAN only while some Ingress, HTTPRoute or
	// Gateway happens to route it, which makes an unrelated routing object
	// load-bearing: deleting it re-issues the certificate without the apex,
	// under the same Key Vault object name the gateway is already serving.
	//
	// It is independent of IssueZoneWildcards. Either flag seeds its own name,
	// so the apex can be covered on its own, and the two together seed both.
	// +optional
	// +kubebuilder:default=false
	IssueZoneApex bool `json:"issueZoneApex,omitempty"`

	// MaxCertificates caps how many certificates may be planned. The overflow is
	// reported in status rather than issued.
	//
	// At the cap, certificates that already exist keep their slot and the new
	// one overflows. The alternative -- planning the first N by name -- means
	// adding a zone that sorts early evicts an unrelated certificate, and under
	// orphanPolicy: Prune, out of the plan means deleted.
	// +optional
	// +kubebuilder:default=10
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	MaxCertificates int32 `json:"maxCertificates,omitempty"`

	// Discovery selects the sources of hostnames.
	// +optional
	Discovery *DiscoverySpec `json:"discovery,omitempty"`

	// Grouping selects how SANs are packed into certificates.
	// +optional
	// +kubebuilder:default=PerZone
	Grouping CertificateGrouping `json:"grouping,omitempty"`

	// IssuerRef names the cert-manager issuer used for DNS-01.
	//
	// Wildcards cannot use HTTP-01, so the issuer must be configured with a
	// DNS-01 solver. DNS-01 never touches the cluster, which is why no pod,
	// Service or Ingress is needed to satisfy the challenge.
	// +required
	IssuerRef IssuerReference `json:"issuerRef"`

	// CertificateNamespace is where the cert-manager Certificate resources, the
	// resulting Secrets and the generated sync resources are created.
	// +required
	// +kubebuilder:validation:MinLength=1
	CertificateNamespace string `json:"certificateNamespace"`

	// KeyVault identifies the destination vault.
	// +required
	KeyVault KeyVaultSpec `json:"keyVault"`

	// CertificateNames pins the Key Vault object name a zone's certificate is
	// imported into, keyed by zone. Unpinned zones keep the name derived from
	// the certificate's SANs, e.g. "*.x.com" becomes "wildcard-x-com".
	//
	// This exists for adoption. An Application Gateway listener references a
	// Key Vault object by name, and repointing a live listener is a cutover, so
	// a platform moving onto this operator needs the certificate to land on the
	// name it already serves -- "ingress-certificate" -- rather than on the
	// derived one.
	//
	// Only the Key Vault object name changes. The cert-manager Certificate, its
	// Secret and the generated KeyVaultCertificateSync keep their derived names,
	// because that is how this policy recognises its own output: renaming them
	// would orphan everything already issued and re-issue the lot against Let's
	// Encrypt's duplicate-certificate limit. status.requiredCertificates[].name
	// therefore stays derived too, while the secretIdentifier beside it -- the
	// value the listener is configured with -- carries the pinned name.
	//
	// Every key must be a zone from Zones, and no two zones may pin the same
	// name: one Key Vault object cannot hold two different certificates. A zone
	// with nothing planned yet is not an error, it simply has no certificate to
	// name; issueZoneWildcards makes the zone's certificate exist regardless of
	// what the cluster routes.
	// +optional
	// +kubebuilder:validation:MaxProperties=50
	CertificateNames map[string]VaultObjectName `json:"certificateNames,omitempty"`

	// OrphanPolicy decides what happens to no-longer-required certificates.
	//
	// Prune is guarded: pruning is judged against the current discovery pass, so
	// the operator withholds it when that pass planned nothing at all, or when a
	// source the policy explicitly enabled was unavailable at startup. Either
	// case is reported as PruneWithheld rather than acted on, because deleting a
	// generated Certificate destroys the issued Secret. Setting
	// IssueZoneWildcards removes the empty-pass case by making the plan
	// independent of discovery.
	// +optional
	// +kubebuilder:default=Retain
	OrphanPolicy OrphanPolicy `json:"orphanPolicy,omitempty"`

	// SyncPolicy is applied to every generated sync resource.
	// +optional
	SyncPolicy *SyncPolicySpec `json:"syncPolicy,omitempty"`
}

// PlannedCertificate is one certificate discovery decided the cluster needs.
type PlannedCertificate struct {
	// Name is the cert-manager Certificate and the generated sync resource. The
	// Key Vault object it imports into is the last path element of
	// SecretIdentifier, which spec.certificateNames may pin to another name.
	Name string `json:"name"`
	// Zone is the allowlisted zone it was planned under.
	Zone string `json:"zone"`
	// DNSNames are the subject alternative names it must carry, truncated to
	// the first 100. The issued Certificate always carries the full set; only
	// this report is bounded, because an unbounded status field would put every
	// SAN of every certificate into etcd on every reconcile.
	// +kubebuilder:validation:MaxItems=100
	DNSNames []string `json:"dnsNames"`
	// SecretName is the Secret cert-manager writes.
	SecretName string `json:"secretName"`
	// SecretIdentifier is the versionless Key Vault URI for the listener.
	SecretIdentifier string `json:"secretIdentifier"`
}

// SkippedHost records a discovered hostname that was deliberately not covered.
type SkippedHost struct {
	// Host is the hostname.
	Host string `json:"host"`
	// Reason explains why it was skipped.
	Reason string `json:"reason"`
}

// ListenerGuidance is a ready-to-apply Application Gateway listener.
type ListenerGuidance struct {
	// Hostnames for one multi-site listener. Application Gateway allows at most
	// five per listener, so a certificate with more SANs than that yields
	// several entries here.
	// +kubebuilder:validation:MaxItems=5
	Hostnames []string `json:"hostnames"`
	// KeyVaultSecretID is the versionless secret identifier to configure. Using
	// a versioned one would permanently disable automatic rotation.
	KeyVaultSecretID string `json:"keyVaultSecretID"`
}

// ApplicationGatewayGuidance is emitted as data for Terraform or the CLI to
// consume. The operator holds no ARM permissions and never writes gateway
// configuration itself.
type ApplicationGatewayGuidance struct {
	// Listeners is the set of listeners needed to serve every planned
	// certificate, truncated to 100. ListenerCount reports the true total.
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Listeners []ListenerGuidance `json:"listeners,omitempty"`

	// ListenerCount is how many listeners the plan actually needs.
	//
	// Worth reading rather than counting the list above: Application Gateway
	// allows 100 active listeners per gateway, hard, so a count above 100 does
	// not merely mean this report was truncated -- it means the plan does not
	// fit on one gateway.
	// +optional
	ListenerCount int32 `json:"listenerCount,omitempty"`
}

// WildcardCertificatePolicyStatus reports the observed state of discovery.
type WildcardCertificatePolicyStatus struct {
	// Conditions holds Ready, Discovered and CertManagerAvailable.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// DiscoveredHosts counts the hostnames found. It is a count rather than a
	// list because a large cluster would otherwise put an unbounded value into
	// etcd.
	// +optional
	DiscoveredHosts int32 `json:"discoveredHosts,omitempty"`

	// RequiredCertificates is the planned certificate set. It is bounded by
	// spec.maxCertificates, which the API server caps at 100.
	// +optional
	// +kubebuilder:validation:MaxItems=100
	RequiredCertificates []PlannedCertificate `json:"requiredCertificates,omitempty"`

	// RequiredCertificateCount is how many certificates the plan contains.
	// +optional
	RequiredCertificateCount int32 `json:"requiredCertificateCount,omitempty"`

	// SkippedHosts lists hostnames that were not covered, with reasons. It is
	// truncated to a bounded sample; SkippedHostCount reports the true total.
	// +optional
	// +kubebuilder:validation:MaxItems=50
	SkippedHosts []SkippedHost `json:"skippedHosts,omitempty"`

	// SkippedHostCount is the total number of skipped hostnames.
	// +optional
	SkippedHostCount int32 `json:"skippedHostCount,omitempty"`

	// ApplicationGateway is the listener configuration to apply out of band.
	// +optional
	ApplicationGateway *ApplicationGatewayGuidance `json:"applicationGateway,omitempty"`

	// LastDiscoveryTime is when discovery last completed.
	// +optional
	LastDiscoveryTime *metav1.Time `json:"lastDiscoveryTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=wcp,categories=certsync
// +kubebuilder:printcolumn:name="Zones",type=string,JSONPath=`.spec.zones`
// +kubebuilder:printcolumn:name="Certificates",type=integer,JSONPath=`.status.requiredCertificateCount`
// +kubebuilder:printcolumn:name="Hosts",type=integer,JSONPath=`.status.discoveredHosts`,priority=1
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WildcardCertificatePolicy discovers the hostnames the cluster routes, decides
// which wildcard certificates cover them, has cert-manager issue those, and
// keeps them synced into Azure Key Vault.
//
// It exists because Application Gateway's per-gateway limits -- 100 backend
// pools, 100 backend HTTP settings, 100 active listeners, 100 SSL certificates,
// all hard -- make one listener per service unworkable past roughly a hundred
// applications. A handful of wildcard certificates uses a few percent of those
// budgets no matter how many services sit behind the in-cluster proxy.
type WildcardCertificatePolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec WildcardCertificatePolicySpec `json:"spec"`
	// +optional
	Status WildcardCertificatePolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WildcardCertificatePolicyList contains a list of WildcardCertificatePolicy.
type WildcardCertificatePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WildcardCertificatePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &WildcardCertificatePolicy{}, &WildcardCertificatePolicyList{})
		return nil
	})
}
