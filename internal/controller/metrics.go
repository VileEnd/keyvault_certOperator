// Package controller contains the Kubernetes adapters that drive the use cases
// in internal/app. The controllers stay thin: they translate resources into use
// case calls and translate the results back into conditions, events and requeue
// decisions.
package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	syncTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certsync_sync_total",
		Help: "Certificate syncs by outcome.",
	}, []string{"namespace", "name", "result"})

	// certificateNotAfter is the metric that actually earns its keep. Reconcile
	// counters cannot distinguish a healthy operator from one that is running
	// happily while every certificate quietly ages out; an expiry timestamp can.
	certificateNotAfter = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certsync_certificate_not_after_timestamp_seconds",
		Help: "Expiry of the synced certificate, in unix seconds.",
	}, []string{"namespace", "name", "certificate"})

	lastSuccessTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certsync_last_success_timestamp_seconds",
		Help: "When this resource last reconciled successfully, in unix seconds.",
	}, []string{"namespace", "name"})

	certificatesRequired = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certsync_certificates_required",
		Help: "Certificates a policy currently requires.",
	}, []string{"policy"})

	hostsSkipped = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certsync_hosts_skipped",
		Help: "Discovered hostnames a policy is not covering.",
	}, []string{"policy"})
)

func init() {
	metrics.Registry.MustRegister(
		syncTotal,
		certificateNotAfter,
		lastSuccessTimestamp,
		certificatesRequired,
		hostsSkipped,
	)
}
