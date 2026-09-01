// Package kube adapts Kubernetes resources to the ports declared in internal/app.
package kube

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

// SecretSource implements app.CertificateSource over a Kubernetes client.
type SecretSource struct {
	Reader client.Reader

	// Uncached reads straight from the API server, past the label-selected
	// Secret cache. It exists for one question the cache cannot answer: whether
	// a Secret the cache does not hold is absent or merely unlabelled. Optional;
	// without it the two stay indistinguishable and both report as not found.
	Uncached client.Reader
}

// NewSecretSource wires a SecretSource that sees only what the cache holds.
func NewSecretSource(reader client.Reader) *SecretSource {
	return &SecretSource{Reader: reader}
}

// WithVisibilityProbe attaches the uncached reader that lets a cache miss be
// explained rather than merely reported. See SecretSource.Uncached.
func (s *SecretSource) WithVisibilityProbe(uncached client.Reader) *SecretSource {
	s.Uncached = uncached
	return s
}

// Load reads a kubernetes.io/tls Secret and parses it into a bundle.
//
// The Secret's type is checked rather than assumed. "kubectl create secret tls"
// validates little more than that the key and certificate pair up, so the
// parsing in the domain layer treats the contents as untrusted -- it identifies
// the leaf by key match and rebuilds the chain rather than trusting order.
func (s *SecretSource) Load(ctx context.Context, ref app.SecretRef) (*domain.Bundle, error) {
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}
	if err := s.Reader.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, s.explainCacheMiss(ctx, ref, key, err)
		}
		return nil, fmt.Errorf("reading secret %s: %w", ref, err)
	}

	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("%w: secret %s has type %q, want %q",
			domain.ErrInvalidSourceSecret, ref, secret.Type, corev1.SecretTypeTLS)
	}

	certPEM, ok := secret.Data[corev1.TLSCertKey]
	if !ok || len(certPEM) == 0 {
		return nil, fmt.Errorf("%w: secret %s has no %s", domain.ErrInvalidSourceSecret, ref, corev1.TLSCertKey)
	}
	keyPEM, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok || len(keyPEM) == 0 {
		return nil, fmt.Errorf("%w: secret %s has no %s", domain.ErrInvalidSourceSecret, ref, corev1.TLSPrivateKeyKey)
	}

	bundle, err := domain.ParseBundle(certPEM, keyPEM)
	if err != nil {
		// The error deliberately names only the Secret and the failure mode.
		// Certificate and key material must never reach the logs.
		return nil, fmt.Errorf("parsing secret %s: %w", ref, err)
	}
	return bundle, nil
}

// explainCacheMiss decides which of two situations a cache miss is: the Secret
// has not been issued yet, or it exists and is invisible because it lacks the
// label the Secret cache selects on. They read identically in the status and
// need opposite fixes, and the operator is the only component that can tell
// them apart -- the cache is never sent an unlabelled Secret at all.
//
// The probe reads metadata only. Fetching the Secret itself would pull the
// private key of an object the cache selector deliberately keeps out of this
// process into memory, purely to phrase an error.
//
// Anything unexpected falls back to the not-found error: the probe may be
// refused outright on a namespace-scoped install, and a guess dressed up as a
// diagnosis is worse than the plain truth.
func (s *SecretSource) explainCacheMiss(
	ctx context.Context, ref app.SecretRef, key types.NamespacedName, notFound error,
) error {
	// Wrapped so that apierrors.IsNotFound still reports true upstream: the
	// controller distinguishes "not issued yet" from a real failure.
	absent := fmt.Errorf("secret %s not found "+
		"(if it exists, check it carries the %s=%s label, without which it is "+
		"outside this operator's cache): %w",
		ref, v1alpha1.LabelManaged, v1alpha1.LabelManagedValue, notFound)

	if s.Uncached == nil {
		return absent
	}

	var metadata metav1.PartialObjectMetadata
	metadata.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
	if err := s.Uncached.Get(ctx, key, &metadata); err != nil {
		return absent
	}
	if metadata.Labels[v1alpha1.LabelManaged] == v1alpha1.LabelManagedValue {
		// Present and labelled: the informer has simply not delivered it yet.
		// The watch event is already on its way, so this is still the waiting
		// state and not a misconfiguration.
		return absent
	}

	return fmt.Errorf("%w: secret %s exists but is not labelled %s=%s, so it is outside "+
		"the label selector this operator's Secret cache watches; label the Secret to "+
		"make it visible",
		domain.ErrSourceSecretNotVisible, ref, v1alpha1.LabelManaged, v1alpha1.LabelManagedValue)
}
