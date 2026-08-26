package kube_test

import (
	"fmt"
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

// gatewayWith builds a Gateway whose listeners carry the given hostnames. An
// empty string means a listener with no hostname at all, which matches every
// name the gateway receives.
func gatewayWith(namespace, name string, hostnames ...string) *gatewayv1.Gateway {
	listeners := make([]gatewayv1.Listener, 0, len(hostnames))
	for i, host := range hostnames {
		listener := gatewayv1.Listener{
			Name:     gatewayv1.SectionName(fmt.Sprintf("l%d", i)),
			Port:     gatewayv1.PortNumber(80 + i),
			Protocol: gatewayv1.HTTPProtocolType,
		}
		if host != "" {
			hostname := gatewayv1.Hostname(host)
			listener.Hostname = &hostname
		}
		listeners = append(listeners, listener)
	}
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       gatewayv1.GatewaySpec{GatewayClassName: "envoy", Listeners: listeners},
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
		gatewayWith("envoy-gateway-system", "eg", "*.x.com"),
	}

	tests := []struct {
		name     string
		ingress  bool
		routes   bool
		gateways bool
		want     []string
	}{
		{"all", true, true, true, []string{"*.x.com", "new.x.com", "old.x.com"}},
		{"ingress only", true, false, false, []string{"old.x.com"}},
		{"httproutes only", false, true, false, []string{"new.x.com"}},
		{"gateways only", false, false, true, []string{"*.x.com"}},
		{"gateway api only", false, true, true, []string{"*.x.com", "new.x.com"}},
		{"none", false, false, false, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := fake.NewClientBuilder().WithScheme(routingScheme(t)).WithObjects(objects...).Build()
			source := &kube.HostSource{
				Reader:            c,
				IncludeIngress:    tc.ingress,
				IncludeHTTPRoutes: tc.routes,
				IncludeGateways:   tc.gateways,
			}

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
		Reader:            c,
		IncludeIngress:    true,
		IncludeHTTPRoutes: true,
		IncludeGateways:   true,
		NamespaceSelector: selector,
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

// The case that motivated reading Gateways at all: a route that states no
// hostnames of its own inherits everything its listener allows. Reading routes
// alone discovers nothing here, which behind a single wildcard listener -- the
// usual Envoy Gateway shape -- means discovering nothing at all.
func TestHostSourceCollectsListenerHostnamesForRoutesThatInheritThem(t *testing.T) {
	t.Parallel()
	objects := []client.Object{
		gatewayWith("envoy-gateway-system", "eg", "*.x.com"),
		// No hostnames: this route serves whatever the listener allows.
		httpRouteWith("apps", "inherits"),
	}
	c := fake.NewClientBuilder().WithScheme(routingScheme(t)).WithObjects(objects...).Build()

	routesOnly := &kube.HostSource{Reader: c, IncludeHTTPRoutes: true}
	got, err := routesOnly.Hosts(t.Context())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("routes alone found %v; the hostname lives on the listener, so this should be empty", got)
	}

	withGateways := &kube.HostSource{Reader: c, IncludeHTTPRoutes: true, IncludeGateways: true}
	got, err = withGateways.Hosts(t.Context())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if want := []string{"*.x.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hosts = %v, want %v", got, want)
	}
}

func TestHostSourceMergesListenerAndRouteHostnames(t *testing.T) {
	t.Parallel()
	objects := []client.Object{
		gatewayWith("envoy-gateway-system", "eg", "*.x.com", "*.sub.x.com"),
		httpRouteWith("apps", "narrowed", "a.x.com"),
	}
	c := fake.NewClientBuilder().WithScheme(routingScheme(t)).WithObjects(objects...).Build()
	source := &kube.HostSource{Reader: c, IncludeHTTPRoutes: true, IncludeGateways: true}

	got, err := source.Hosts(t.Context())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	want := []string{"*.sub.x.com", "*.x.com", "a.x.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hosts = %v, want %v", got, want)
	}
}

// A listener with no hostname matches every name the gateway receives. There is
// nothing concrete to derive a certificate from, so it must contribute nothing
// rather than an invented name.
func TestHostSourceIgnoresListenersWithoutAHostname(t *testing.T) {
	t.Parallel()
	c := fake.NewClientBuilder().WithScheme(routingScheme(t)).
		WithObjects(gatewayWith("envoy-gateway-system", "eg", "", "*.x.com")).Build()
	source := &kube.HostSource{Reader: c, IncludeGateways: true}

	got, err := source.Hosts(t.Context())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if want := []string{"*.x.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hosts = %v, want %v", got, want)
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
