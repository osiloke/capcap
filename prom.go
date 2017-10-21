package capcap

import (
	"github.com/prometheus/client_golang/prometheus"
)

//Metrics
var (
	labels = []string{
		// Which interface
		"interface",
		// Which worker
		"worker",
	}

	mActiveFlows = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gotm_active_flow_count",
			Help: "Current number of active flows",
		}, labels,
	)
	mExpired = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gotm_expired_flow_count",
			Help: "Current number of expired flows in the last packetTimeInterval",
		}, labels,
	)
	mExpiredDurTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_expired_flow_duration_seconds_sum",
			Help: "Total time spent expiring flows",
		}, labels,
	)
	mBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_bytes_total",
			Help: "Number of bytes seen",
		}, labels,
	)
	mBytesOutput = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_bytes_output_total",
			Help: "Number of bytes output after filtering",
		}, labels,
	)
	mPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_packet_count",
			Help: "Number of packets seen",
		}, labels,
	)
	mOutput = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_packet_output_count",
			Help: "Number of packets output after filtering",
		}, labels,
	)
	mFlows = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_flow_count",
			Help: "Number of flows seen",
		}, labels,
	)

	mFlowSize = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "gotm_flow_size_bytes",
			Help:    "Bytes per flow",
			Buckets: prometheus.ExponentialBuckets(1024, 4, 15),
		},
	)

	// These should be gauges, but can't.. https://github.com/prometheus/client_golang/issues/309
	mReceived = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gotm_packet_nic_received",
			Help: "Number of packets received by NIC",
		}, labels,
	)
	mDropped = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gotm_packet_nic_dropped",
			Help: "Number of packets dropped by NIC",
		}, labels,
	)
	mIfDropped = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gotm_packet_nic_if_dropped",
			Help: "Number of packets dropped by NIC at the interface",
		}, labels,
	)
)
