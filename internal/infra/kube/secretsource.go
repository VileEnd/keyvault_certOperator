// Package kube adapts Kubernetes resources to the ports declared in internal/app.
package kube

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/VileEnd/keyvault_certOperator/api/v1alpha1"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

// SecretSource implements app.CertificateSource over a Kubernetes client.
type SecretSource struct {
	Reader client.Reader
}

// NewSecretSource wires a SecretSource.
func NewSecretSource(reader client.Reader) *SecretSource {
	return &SecretSource{Reader: reader}
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
			return nil, fmt.Errorf("secret %s not found "+
				"(it must carry the %s=%s label to be visible to this operator): %w",
				ref, v1alpha1.LabelManaged, v1alpha1.LabelManagedValue, err)
		}
		return nil, fmt.Errorf("reading secret %s: %w", ref, err)
	}

	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("secret %s has type %q, want %q", ref, secret.Type, corev1.SecretTypeTLS)
	}

	certPEM, ok := secret.Data[corev1.TLSCertKey]
	if !ok || len(certPEM) == 0 {
		return nil, fmt.Errorf("secret %s has no %s", ref, corev1.TLSCertKey)
	}
	keyPEM, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok || len(keyPEM) == 0 {
		return nil, fmt.Errorf("secret %s has no %s", ref, corev1.TLSPrivateKeyKey)
	}

	bundle, err := domain.ParseBundle(certPEM, keyPEM)
	if err != nil {
		// The error deliberately names only the Secret and the failure mode.
		// Certificate and key material must never reach the logs.
		return nil, fmt.Errorf("parsing secret %s: %w", ref, err)
	}
	return bundle, nil
}
