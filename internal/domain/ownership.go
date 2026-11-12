package domain

import "fmt"

// OwnershipMode decides which existing Key Vault certificates a sync may
// import over.
//
// The certificate name is chosen by whoever writes the sync resource, and an
// Application Gateway listener serves whatever is stored under the name it was
// given. Without a check, anyone able to create a sync resource in a watched
// namespace could name the certificate a listener already uses and replace it
// with one of their own.
type OwnershipMode string

const (
	// OwnershipAdoptUntagged refuses to import over a certificate this operator
	// synced from a different Secret, but still takes over one that carries no
	// ownership tags at all -- uploaded by hand, or replaced out of band. This
	// is the default: it is what makes adopting an existing certificate and
	// correcting drift keep working.
	OwnershipAdoptUntagged OwnershipMode = "adopt-untagged"
	// OwnershipStrict additionally refuses untagged certificates, so a sync can
	// only ever write to a name that is free or already its own.
	OwnershipStrict OwnershipMode = "strict"
	// OwnershipOff performs no check, which is the behaviour that existed
	// before this type.
	OwnershipOff OwnershipMode = "off"
)

// ParseOwnershipMode validates a mode, treating empty as the default.
func ParseOwnershipMode(value string) (OwnershipMode, error) {
	switch mode := OwnershipMode(value); mode {
	case "":
		return OwnershipAdoptUntagged, nil
	case OwnershipAdoptUntagged, OwnershipStrict, OwnershipOff:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown vault ownership mode %q; expected one of %s, %s, %s",
			value, OwnershipAdoptUntagged, OwnershipStrict, OwnershipOff)
	}
}

// CheckOwnership reports whether a sync reading from source may import over
// what the vault currently holds. source is "namespace/name" of the Secret.
//
// It is only meaningful ahead of an import. A certificate that already matches
// is left alone whoever owns it, since nothing is written.
func CheckOwnership(snap VaultSnapshot, source string, mode OwnershipMode) error {
	if !snap.Exists || mode == OwnershipOff {
		return nil
	}
	if snap.ManagedSource != "" {
		if snap.ManagedSource == source {
			return nil
		}
		return fmt.Errorf("%w: it is synced from %s, not %s; choose another certificateName, "+
			"or delete the sync resource that owns it and the certificate in Key Vault",
			ErrVaultCertificateNotOwned, snap.ManagedSource, source)
	}
	if mode == OwnershipStrict {
		return fmt.Errorf("%w: it was not created by this operator, and --vault-ownership=strict "+
			"does not adopt existing certificates", ErrVaultCertificateNotOwned)
	}
	return nil
}
