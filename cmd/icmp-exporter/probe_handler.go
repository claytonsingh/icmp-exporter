package main

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"

	"github.com/claytonsingh/icmp-exporter/netprobe"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// W gets the weight for this sample
func W(n int, l int) float32 {
	if n < 25 || l-n < 25 {
		return 0
	}
	return 1
}

func ProbeHander(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	targets := make(map[string]net.IP)

	if !params.Has("target") {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(([]byte)("# 400 - missing parameter target"))
		return
	}

	// If limit header is set then use that if its less then 256
	// If the limit header is not a number then the limit is 0
	limit := 256
	for _, lim := range r.Header.Values("x-target-limit") {
		lim, _ := strconv.Atoi(lim)
		if lim < limit {
			limit = lim
		}
	}

	// Loop over each target and add the resolved ips to targets
	for _, target := range params["target"] {
		ip := net.ParseIP(target)
		if ip != nil {
			targets[string(ip)] = ip
		} else {
			addresses, err := resolver.Resolve(target)
			if err != nil {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusBadRequest)
				w.Write(([]byte)("# 400 - unable to resolve target=\"" + target + "\""))
				return
			}

			switch params.Get("ip_version") {
			case "4":
				for _, ip := range addresses {
					if netprobe.IsIPv4(ip) && ip.IsGlobalUnicast() {
						targets[string(ip)] = ip
					}
				}
			case "6":
				for _, ip := range addresses {
					if netprobe.IsIPv6(ip) && ip.IsGlobalUnicast() {
						targets[string(ip)] = ip
					}
				}
			default:
				for _, ip := range addresses {
					if ip.IsGlobalUnicast() {
						targets[string(ip)] = ip
					}
				}
			}

			// Exit early if we have exceed the limit
			if len(targets) > limit {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusBadRequest)
				w.Write(([]byte)("# 400 - too many targets"))
				return
			}
		}
	}

	// Parse TCP port parameter
	// If TCP ports are specified, return TCP metrics
	// If no TCP ports are specified, return ICMP metrics
	tcpPorts := make(map[uint16]struct{})
	if params.Has("tcp_port") {
		for _, tcpPortStr := range params["tcp_port"] {
			port, err := strconv.Atoi(tcpPortStr)
			if err != nil || port < 1 || port > 65535 {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusBadRequest)
				w.Write(([]byte)("# 400 - invalid tcp_port parameter"))
				return
			}
			tcpPorts[uint16(port)] = struct{}{}
		}
	}

	// We still need to set tcpPorts when returning ICMP metrics
	returnTcpMetrics := len(tcpPorts) > 0
	if len(tcpPorts) == 0 {
		tcpPorts[0] = struct{}{}
	}

	if len(tcpPorts)*len(targets) > limit {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(([]byte)("# 400 - too many targets"))
		return
	}

	registry := prometheus.NewRegistry()

	// Create metrics based on whether we're returning TCP or ICMP metrics
	var probeSentTotal, probeRecvTotal, probeLatencyTotal, probeLatencySqTotal *prometheus.CounterVec
	var probeLatency, probeDeviation, probeLoss, probeSamples *prometheus.GaugeVec

	if returnTcpMetrics {
		// TCP metrics
		probeSentTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tcp_probe_packets_sent_total",
			Help: "How many tcp packets were sent to the target ip",
		}, []string{"ip", "tcp_port"})
		registry.MustRegister(probeSentTotal)

		probeRecvTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tcp_probe_packets_recv_total",
			Help: "How many tcp packets were recieved from the target ip",
		}, []string{"ip", "tcp_port"})
		registry.MustRegister(probeRecvTotal)

		probeLatencyTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tcp_probe_latency_seconds_total",
			Help: "",
		}, []string{"ip", "tcp_port"})
		registry.MustRegister(probeLatencyTotal)

		probeLatencySqTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tcp_probe_latency_squared_seconds_total",
			Help: "",
		}, []string{"ip", "tcp_port"})
		registry.MustRegister(probeLatencySqTotal)

		probeLatency = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tcp_probe_latency_seconds",
			Help: "",
		}, []string{"ip", "tcp_port"})
		registry.MustRegister(probeLatency)

		probeDeviation = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tcp_probe_standard_deviation_seconds",
			Help: "",
		}, []string{"ip", "tcp_port"})
		registry.MustRegister(probeDeviation)

		probeLoss = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tcp_probe_loss_ratio",
			Help: "",
		}, []string{"ip", "tcp_port"})
		registry.MustRegister(probeLoss)

		probeSamples = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tcp_probe_samples_count",
			Help: "",
		}, []string{"ip", "tcp_port"})
		registry.MustRegister(probeSamples)
	} else {
		// ICMP metrics
		probeSentTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "icmp_probe_packets_sent_total",
			Help: "How many icmp packets were sent to the target ip",
		}, []string{"ip"})
		registry.MustRegister(probeSentTotal)

		probeRecvTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "icmp_probe_packets_recv_total",
			Help: "How many icmp packets were recieved from the target ip",
		}, []string{"ip"})
		registry.MustRegister(probeRecvTotal)

		probeLatencyTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "icmp_probe_latency_seconds_total",
			Help: "",
		}, []string{"ip"})
		registry.MustRegister(probeLatencyTotal)

		probeLatencySqTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "icmp_probe_latency_squared_seconds_total",
			Help: "",
		}, []string{"ip"})
		registry.MustRegister(probeLatencySqTotal)

		probeLatency = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "icmp_probe_latency_seconds",
			Help: "",
		}, []string{"ip"})
		registry.MustRegister(probeLatency)

		probeDeviation = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "icmp_probe_standard_deviation_seconds",
			Help: "",
		}, []string{"ip"})
		registry.MustRegister(probeDeviation)

		probeLoss = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "icmp_probe_loss_ratio",
			Help: "",
		}, []string{"ip"})
		registry.MustRegister(probeLoss)

		probeSamples = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "icmp_probe_samples_count",
			Help: "",
		}, []string{"ip"})
		registry.MustRegister(probeSamples)
	}

	// Process probes and populate metrics
	for _, target := range targets {
		// Process probes; when returning ICMP tcpPorts is ignored but has one element
		for tcpPort := range tcpPorts {
			job, new := GetProbe(target, tcpPort)
			if new {
				signal.Signal()
			}

			var labels []string
			if returnTcpMetrics {
				labels = []string{fmt.Sprintf("%s", job.IPAddress.String()), fmt.Sprintf("%d", job.TCPPort)}
			} else {
				labels = []string{fmt.Sprintf("%s", job.IPAddress.String())}
			}

			job.Mutex.Lock()
			probeSentTotal.WithLabelValues(labels...).Add(float64(job.SentCount))
			probeRecvTotal.WithLabelValues(labels...).Add(float64(job.RecvCount))
			probeLatencyTotal.WithLabelValues(labels...).Add(float64(job.RoundtripTotal) / 1000000.0)
			probeLatencySqTotal.WithLabelValues(labels...).Add(float64(job.RoundtripSqTotal) / (1000000.0 * 1000000.0))

			// Take a snapshot of the results and copy pointers into a new array
			results := job.Results.Snapshot()
			if job.ResultLimit < len(results) {
				results = results[len(results)-job.ResultLimit:]
			}
			job.Mutex.Unlock()

			var a, b int
			for _, r := range results {
				if r.Success {
					a += 1
				}
			}

			var maxScore float32 = 0.12
			var maxIndex int = len(results)
			var sumRTT int64 = 0
			var sumRTT2 int64 = 0
			var bestRTT int64 = 0
			var bestLoss int = 0
			var bestSumRTT int64 = 0
			var bestSumRTT2 int64 = 0
			var lastResult *netprobe.PingResult
			for n := range results {
				r := &results[len(results)-1-n]

				if r.Success {
					sumRTT += r.RountripTime
					sumRTT2 += r.RountripTime * r.RountripTime
				}

				w := W(n, len(results))
				if w > 0 {
					// After and Before averages
					aavg := float32(a) / float32(len(results)-n)
					bavg := float32(b) / float32(n)
					cavg := aavg - bavg
					if cavg < 0 {
						cavg = -cavg
					}
					score := cavg * w

					if score > maxScore {
						maxScore = score
						maxIndex = n
						bestRTT = sumRTT
						bestLoss = b
						bestSumRTT = sumRTT
						bestSumRTT2 = sumRTT2
						lastResult = r
					}
				}
				if r.Success {
					a -= 1
					b += 1
				}
			}

			if maxIndex == len(results) {
				bestLoss = b
				bestRTT = sumRTT
				bestSumRTT = sumRTT
				bestSumRTT2 = sumRTT2
			}
			if lastResult != nil && maxIndex >= 100 {
				job.Mutex.Lock()
				for n := range job.Results.Snapshot() {
					if &results[len(results)-n-1] == lastResult {
						job.ResultLimit = n
						break
					}
				}
				job.Mutex.Unlock()
			}

			probeLoss.WithLabelValues(labels...).Set(1.0 - float64(bestLoss)/(float64(maxIndex)))
			probeSamples.WithLabelValues(labels...).Set(float64(maxIndex))
			probeLatency.WithLabelValues(labels...).Set(float64(bestRTT) / (float64(bestLoss * 1000000.0)))

			// mean = sum_x / n
			// stdev = sqrt((sum_x2 / n) - (mean * mean))
			mean := (float64(bestSumRTT) / 1000000.0) / float64(maxIndex)
			mean2 := (float64(bestSumRTT2) / (1000000.0 * 1000000.0)) / float64(maxIndex)
			probeDeviation.WithLabelValues(labels...).Set(math.Sqrt(mean2 - mean*mean))
		}
	}

	w.Header().Set("x-target-count", fmt.Sprintf("%d", len(targets)))
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}
