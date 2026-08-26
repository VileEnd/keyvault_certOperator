package v1alpha1

const (
	// LabelManaged marks the Secrets this operator is allowed to read.
	//
	// The manager's cache is restricted to Secrets carrying this label, so the
	// operator never holds unrelated Secrets -- or their private keys -- in
	// memory. Generated certificates get the label stamped on their Secret via
	// cert-manager's secretTemplate; a hand-written sync needs it applied to the
	// Secret directly.
	LabelManaged = "certsync.vileend.io/managed"
	// LabelManagedValue is the value expected for LabelManaged.
	LabelManagedValue = "true"

	// LabelPolicy records which WildcardCertificatePolicy generated a resource.
	LabelPolicy = "certsync.vileend.io/policy"
	// LabelCertificate records the planned certificate a resource belongs to.
	LabelCertificate = "certsync.vileend.io/certificate"

	// FinalizerName is set on resources this operator owns.
	//
	// It exists only to make deletion observable and orderly. It never blocks on
	// Azure: the Key Vault certificate is deliberately left in place, because an
	// Application Gateway listener may still be serving it and deleting it would
	// take that listener down.
	FinalizerName = "certsync.vileend.io/finalizer"
)
