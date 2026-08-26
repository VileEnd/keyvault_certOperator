package kube_test

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/VileEnd/keyvault_certOperator/internal/infra/kube"
)

func routingScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("building scheme: %v", err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatalf("installing gateway-api: %v", err)
	}
	return scheme
}

func ingressWith(namespace, name string, ruleHosts, tlsHosts []string) *networkingv1.Ingress {
	rules := make([]networkingv1.IngressRule, 0, len(ruleHosts))
	for _, host := range ruleHosts {
		rules = append(rules, networkingv1.IngressRule{Host: host})
	}
	var tls []networkingv1.IngressTLS
	if len(tlsHosts) > 0 {
		tls = []networkingv1.IngressTLS{{Hosts: tlsHosts}}
	}
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       networkingv1.IngressSpec{Rules: rules, TLS: tls},
	}
}

func httpRouteWith(namespace, name string, hostnames ...string) *gatewayv1.HTTPRoute {
	hosts := make([]gatewayv1.Hostname, 0, len(hostnames))
	for _, host := range hostnames {
		hosts = append(hosts, gatewayv1.Hostname(host))
	}
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       gatewayv1.HTTPRouteSpec{Hostnames: hosts},
	}
}

func TestHostSourceCollectsRuleAndTLSHosts(t *testing.T) {
	t.Parallel()
	// A rule host is what actually gets routed; a TLS host records an intent to
	// terminate TLS for it. Either is a reason to want a certificate, so both
	// are collected.
	c := fake.NewClientBuilder().WithScheme(routingScheme(t)).
		WithObjects(ingressWith("apps", "shop",
			[]string{"api.x.com"}, []string{"web.x.com", "api.x.com"})).
		Build()

	source := &kube.HostSource{Reader: c, IncludeIngress: true}
	got, err := source.Hosts(t.Context())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}

	// Deduplicated and sorted: an unstable host list would produce an unstable
	// plan, which would churn Certificates and mint pointless Key Vault versions.
	want := []string{"api.x.com", "web.x.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hosts = %v, want %v", got, want)
	}
}

func TestHostSourceCollectsHTTPRouteHostnames(t *testing.T) {
	t.Parallel()
	c := fake.NewClientBuilder().WithScheme(routingScheme(t)).
		WithObjects(
			ingressWith("apps", "legacy", []string{"old.x.com"}, nil),
			httpRouteWith("apps", "modern", "new.x.com", "api.x.com"),
		).Build()

	source := &kube.HostSource{Reader: c, IncludeIngress: true, IncludeHTTPRoutes: true}
	got, err := source.Hosts(t.Context())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}

	want := []string{"api.x.com", "new.x.com", "old.x.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hosts = %v, want %v", got, want)
	}
}

func TestHostSourceRespectsTheDiscoveryToggles(t *testing.T) {
	t.Parallel()
	// HTTPRoutes are only watched when the Gateway API CRDs were present at
	// startup, so the toggle has to genuinely suppress the read.
	objects := []client.Object{
		ingressWith("apps", "legacy", []string{"old.x.com"}, nil),
		httpRouteWith("apps", "modern", "new.x.com"),
	}

	tests := []struct {
		name    string
		ingress bool
		routes  bool
		want    []string
	}{
		{"both", true, true, []string{"new.x.com", "old.x.com"}},
		{"ingress only", true, false, []string{"old.x.com"}},
		{"httproutes only", false, true, []string{"new.x.com"}},
		{"neither", false, false, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := fake.NewClientBuilder().WithScheme(routingScheme(t)).WithObjects(objects...).Build()
			source := &kube.HostSource{Reader: c, IncludeIngress: tc.ingress, IncludeHTTPRoutes: tc.routes}

			got, err := source.Hosts(t.Context())
			if err != nil {
				t.Fatalf("Hosts: %v", err)
			}
			if len(tc.want) == 0 && len(got) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("hosts = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHostSourceHonoursTheNamespaceSelector(t *testing.T) {
	t.Parallel()
	c := fake.NewClientBuilder().WithScheme(routingScheme(t)).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name: "public", Labels: map[string]string{"tier": "public"}}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name: "internal", Labels: map[string]string{"tier": "internal"}}},
			ingressWith("public", "shop", []string{"shop.x.com"}, nil),
			ingressWith("internal", "admin", []string{"admin.x.com"}, nil),
			httpRouteWith("internal", "ops", "ops.x.com"),
		).Build()

	selector, err := kube.SelectorFrom(&metav1.LabelSelector{MatchLabels: map[string]string{"tier": "public"}})
	if err != nil {
		t.Fatalf("SelectorFrom: %v", err)
	}

	source := &kube.HostSource{
		Reader: c, IncludeIngress: true, IncludeHTTPRoutes: true, NamespaceSelector: selector,
	}
	got, err := source.Hosts(t.Context())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}

	// Hostnames from unselected namespaces must not reach the plan at all --
	// otherwise the selector would not actually bound what can be issued.
	want := []string{"shop.x.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hosts = %v, want %v", got, want)
	}
}

func TestHostSourceIgnoresEmptyHosts(t *testing.T) {
	t.Parallel()
	// A rule with no host is a catch-all; it names nothing to issue for.
	c := fake.NewClientBuilder().WithScheme(routingScheme(t)).
		WithObjects(ingressWith("apps", "catchall", []string{"", "real.x.com"}, nil)).
		Build()

	source := &kube.HostSource{Reader: c, IncludeIngress: true}
	got, err := source.Hosts(t.Context())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"real.x.com"}) {
		t.Errorf("hosts = %v, want [real.x.com]", got)
	}
}

func TestSelectorFrom(t *testing.T) {
	t.Parallel()
	// A nil selector means "every namespace" rather than "none", so it must not
	// produce a selector that filters everything out.
	selector, err := kube.SelectorFrom(nil)
	if err != nil {
		t.Fatalf("SelectorFrom(nil): %v", err)
	}
	if selector != nil {
		t.Errorf("SelectorFrom(nil) = %v, want nil", selector)
	}

	if _, err := kube.SelectorFrom(&metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "t", Operator: "Bogus"}},
	}); err == nil {
		t.Error("expected an error for an invalid selector operator")
	}
}
