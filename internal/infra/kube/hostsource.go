package kube

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// HostSource implements app.HostSource by enumerating the hostnames the cluster
// routes, from Ingress and Gateway API HTTPRoute resources.
type HostSource struct {
	Reader client.Reader

	// IncludeIngress enables discovery from networking.k8s.io Ingresses.
	IncludeIngress bool
	// IncludeHTTPRoutes enables discovery from Gateway API HTTPRoutes. It is set
	// only when the Gateway API CRDs were present at startup, because
	// controller-runtime cannot start an informer for an unknown type.
	IncludeHTTPRoutes bool
	// NamespaceSelector narrows discovery. Nil means every namespace.
	NamespaceSelector labels.Selector
}

// Hosts returns the deduplicated, sorted set of hostnames routed by the cluster.
//
// Both Ingress rule hosts and the hosts named in its TLS blocks are collected:
// a rule host is what actually gets routed, while a TLS host records an intent
// to terminate TLS for it, and either is a reason to want a certificate.
func (h *HostSource) Hosts(ctx context.Context) ([]string, error) {
	allowed, err := h.allowedNamespaces(ctx)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}

	if h.IncludeIngress {
		var list networkingv1.IngressList
		if err := h.Reader.List(ctx, &list); err != nil {
			return nil, fmt.Errorf("listing ingresses: %w", err)
		}
		for i := range list.Items {
			ingress := &list.Items[i]
			if !inNamespace(allowed, ingress.Namespace) {
				continue
			}
			for _, rule := range ingress.Spec.Rules {
				add(seen, rule.Host)
			}
			for _, tls := range ingress.Spec.TLS {
				for _, host := range tls.Hosts {
					add(seen, host)
				}
			}
		}
	}

	if h.IncludeHTTPRoutes {
		var list gatewayv1.HTTPRouteList
		if err := h.Reader.List(ctx, &list); err != nil {
			return nil, fmt.Errorf("listing httproutes: %w", err)
		}
		for i := range list.Items {
			route := &list.Items[i]
			if !inNamespace(allowed, route.Namespace) {
				continue
			}
			for _, hostname := range route.Spec.Hostnames {
				add(seen, string(hostname))
			}
		}
	}

	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	// Sorted so the resulting plan is stable; an unstable plan would churn
	// Certificate resources and mint pointless Key Vault versions.
	sort.Strings(hosts)
	return hosts, nil
}

// allowedNamespaces resolves the namespace selector to a set of names, or nil
// when every namespace is in scope.
func (h *HostSource) allowedNamespaces(ctx context.Context) (map[string]struct{}, error) {
	if h.NamespaceSelector == nil || h.NamespaceSelector.Empty() {
		return nil, nil
	}
	var list corev1.NamespaceList
	if err := h.Reader.List(ctx, &list, client.MatchingLabelsSelector{Selector: h.NamespaceSelector}); err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	allowed := make(map[string]struct{}, len(list.Items))
	for i := range list.Items {
		allowed[list.Items[i].Name] = struct{}{}
	}
	return allowed, nil
}

func inNamespace(allowed map[string]struct{}, namespace string) bool {
	if allowed == nil {
		return true
	}
	_, ok := allowed[namespace]
	return ok
}

func add(seen map[string]struct{}, host string) {
	if host == "" {
		return
	}
	seen[host] = struct{}{}
}

// SelectorFrom converts an API label selector into a labels.Selector.
func SelectorFrom(selector *metav1.LabelSelector) (labels.Selector, error) {
	if selector == nil {
		return nil, nil
	}
	parsed, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("parsing namespace selector: %w", err)
	}
	return parsed, nil
}
