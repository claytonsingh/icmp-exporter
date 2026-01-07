package main

import (
	"github.com/claytonsingh/icmp-exporter/netprobe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// RegisterPingerMetrics registers Prometheus metrics for the pinger using GaugeFunc
func RegisterPingerMetrics(p *netprobe.Native) {
	// ICMP packet counters
	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "icmp_packets_sent_total",
		Help: "The total number of transmitted ICMP packets",
	}, func() float64 {
		return float64(p.ICMPNative.GetSentCount())
	})

	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "icmp_packets_recv_total",
		Help: "The total number of received ICMP packets",
	}, func() float64 {
		return float64(p.ICMPNative.GetReceivedCount())
	})

	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "icmp_packets_error_total",
		Help: "The total number of ICMP error packets",
	}, func() float64 {
		return float64(p.ICMPNative.GetErrorCount())
	})

	// TCP packet counters
	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "tcp_packets_sent_total",
		Help: "The total number of transmitted TCP packets",
	}, func() float64 {
		return float64(p.TCPNative.GetSentCount())
	})

	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "tcp_packets_recv_total",
		Help: "The total number of received TCP packets",
	}, func() float64 {
		return float64(p.TCPNative.GetReceivedCount())
	})

	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "tcp_packets_error_total",
		Help: "The total number of TCP error packets",
	}, func() float64 {
		return float64(p.TCPNative.GetErrorCount())
	})

	// Active probe gauges
	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "icmp_active_probes",
		Help: "The number of active ICMP probes",
	}, func() float64 {
		return float64(p.GetICMPActiveProbes())
	})

	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "tcp_active_probes",
		Help: "The number of active TCP probes",
	}, func() float64 {
		return float64(p.GetTCPActiveProbes())
	})
}
