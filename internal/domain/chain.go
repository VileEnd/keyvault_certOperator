package domain

import (
	"bytes"
	"crypto/x509"
	"sort"
)

// orderChain arranges the non-leaf certificates into issuer order, walking from
// the leaf outwards: leaf's issuer first, then that certificate's issuer, and so
// on.
//
// Order matters downstream. Application Gateway requires the full chain with the
// leaf topmost, and its own troubleshooting guidance lists an incomplete or
// misordered chain as a leading cause of TLS failures. Since the input order
// cannot be trusted, we rebuild it here from the certificates themselves.
//
// Certificates that do not link into the chain are not discarded -- they are
// appended in a stable order so that a partially understood bundle still round
// trips rather than silently losing data.
func orderChain(leaf *x509.Certificate, rest []*x509.Certificate) []*x509.Certificate {
	if len(rest) == 0 {
		return nil
	}

	used := make([]bool, len(rest))
	ordered := make([]*x509.Certificate, 0, len(rest))

	current := leaf
	for {
		idx := findIssuer(current, rest, used)
		if idx < 0 {
			break
		}
		used[idx] = true
		ordered = append(ordered, rest[idx])
		// A self-signed certificate is a root: the chain ends here.
		if isSelfSigned(rest[idx]) {
			break
		}
		current = rest[idx]
	}

	// Append anything that did not link in, in a deterministic order.
	var orphans []*x509.Certificate
	for i, cert := range rest {
		if !used[i] {
			orphans = append(orphans, cert)
		}
	}
	sort.SliceStable(orphans, func(i, j int) bool {
		return bytes.Compare(orphans[i].Raw, orphans[j].Raw) < 0
	})

	return append(ordered, orphans...)
}

// findIssuer returns the index of the certificate that issued child, preferring
// one whose signature actually verifies over a mere name match.
func findIssuer(child *x509.Certificate, candidates []*x509.Certificate, used []bool) int {
	nameMatch := -1
	for i, candidate := range candidates {
		if used[i] || !bytes.Equal(child.RawIssuer, candidate.RawSubject) {
			continue
		}
		if child.CheckSignatureFrom(candidate) == nil {
			return i
		}
		if nameMatch < 0 {
			nameMatch = i
		}
	}
	return nameMatch
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil
}
