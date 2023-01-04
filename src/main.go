package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/abursavich/nett"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PingJob struct {
	IPAddress       net.IP
	Sent_Count      int32
	Recv_Count      int32
	Roundtrip_Total int64 // In microseconds
	Results         PDB
	ResultLimit     int
	LastAccess      time.Time
	Mutex           sync.Mutex
}

func (this *PingJob) AddSample(sample PingResult) {
	this.Mutex.Lock()
	this.Sent_Count += 1
	this.ResultLimit += 1
	if this.ResultLimit > this.Results.Size {
		this.ResultLimit = this.Results.Size
	}

	// var insertAt int
	// elements := this.Results.Snapshot()
	// for i := range elements {
	// 	index := len(elements) - i - 1
	// 	if sample.Timestamp.After(elements[index].Timestamp) {
	// 		insertAt = index + 1
	// 		break
	// 	}
	// }
	// this.Results.Insert(insertAt, sample)

	this.Results.Append(sample)
	if sample.Success {
		this.Recv_Count += 1
		this.Roundtrip_Total += sample.RountripTime
	}
	this.Mutex.Unlock()
}

type PingResult struct {
	Success      bool
	RountripTime int64 // In microseconds
	Timestamp    time.Time
}

var jobMap = sync.Map{}
var signal = NewSignal()
var resolver = nett.CacheResolver{TTL: 5 * time.Minute}

func main() {

	iface := flag.String("interface", "", "Interface to bind to")
	use_hardware := flag.Bool("hard", false, "Use hardware timestamping")
	listen_addr := flag.String("listen", ":9116", "ip and port to listen on, defaults to :9116")
	flag.Parse()

	p := NewICMPNative(*use_hardware, *iface)
	p.Start()

	go func() {
		Wait := signal.GetWaiter(true)
		for {
			Wait()
			r := make([]*PingJob, 0)
			jobMap.Range(func(key any, value any) bool {
				if v, ok := value.(*PingJob); ok {
					r = append(r, v)
				}
				return true
			})
			sort.Slice(r, func(i int, j int) bool {
				return bytes.Compare(r[i].IPAddress, r[j].IPAddress) < 0
			})
			fmt.Println("Updated Job List", len(r))
			p.SetJobs(r)
			time.Sleep(1 * time.Second)
		}
	}()
	go PruneMap()

	// if _, new := GetJob(net.IPv4(10, 10, 0, 1)); new {
	// 	signal.Signal()
	// }

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", ProbeHander)
	http.ListenAndServe(*listen_addr, nil)

	select {}
}

func W(n int, l int) float32 {
	if n < 25 || l-n < 25 {
		return 0
	}
	return 1
}

func ProbeHander(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	var target string = ""

	if params.Has("target") {
		target = params.Get("target")
	} else if params.Has("ip") {
		target = params.Get("ip")
	}

	if target == "" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(([]byte)("# 400 - missing parameter target"))
		return
	}

	requestTarget := target
	requestIp := net.ParseIP(target)
	if requestIp == nil {
		addresses, err := resolver.Resolve(target)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(([]byte)("# 400 - unable to resolve target=\"" + target + "\""))
			return
		}
		sort.Slice(addresses, func(i int, j int) bool {
			return bytes.Compare(addresses[i], addresses[j]) < 0
		})
		for _, address := range addresses {
			if address.IsGlobalUnicast() && bytes.HasPrefix(address.To16(), []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}) {
				requestIp = address
				break
			}
		}
		if requestIp == nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(([]byte)("# 400 - unable to resolve target=\"" + target + "\""))
			return
		}
	}

	registry := prometheus.NewRegistry()

	probeSentCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "probe_sent_count",
		Help: "How many icmp packets were sent to the target ip",
	}, []string{"ip", "target"})
	registry.MustRegister(probeSentCount)

	probeRecvCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "probe_recv_count",
		Help: "How many icmp packets were recieved from the target ip",
	}, []string{"ip", "target"})
	registry.MustRegister(probeRecvCount)

	probeLatencyTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "probe_latency_seconds_total",
		Help: "",
	}, []string{"ip", "target"})
	registry.MustRegister(probeLatencyTotal)

	probeLatency := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_latency_seconds",
		Help: "",
	}, []string{"ip", "target"})
	registry.MustRegister(probeLatency)

	probeLoss := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_loss_ratio",
		Help: "",
	}, []string{"ip", "target"})
	registry.MustRegister(probeLoss)

	probeSamples := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_samples_count",
		Help: "",
	}, []string{"ip", "target"})
	registry.MustRegister(probeSamples)

	job, new := GetJob(requestIp)
	if new {
		signal.Signal()
	}

	labels := []string{job.IPAddress.String(), requestTarget}

	resultsSorted := make([]*PingResult, 0, job.Results.Size)
	job.Mutex.Lock()
	probeSentCount.WithLabelValues(labels...).Add(float64(job.Sent_Count))
	probeRecvCount.WithLabelValues(labels...).Add(float64(job.Recv_Count))
	probeLatencyTotal.WithLabelValues(labels...).Add(float64(job.Roundtrip_Total) / 1000000.0)

	// Take a snapshot of the results and copy pointers into a new array
	results := job.Results.Snapshot()
	if job.ResultLimit < len(results) {
		results = results[len(results)-job.ResultLimit:]
	}
	for n := range results {
		r := &results[len(results)-n-1]
		resultsSorted = append(resultsSorted, r)
	}
	job.Mutex.Unlock()

	// Sort the results since they can be out of order
	sort.Slice(resultsSorted, func(i int, j int) bool {
		return resultsSorted[i].Timestamp.After(resultsSorted[j].Timestamp)
	})

	var a, b int
	for _, r := range resultsSorted {
		if r.Success {
			a += 1
		}
	}

	var maxScore float32 = 0.12
	var maxIndex int = len(resultsSorted)
	var sumRTT int64 = 0
	var sumRTT2 int64 = 0
	var bestRTT int64 = 0
	var bestLoss int = 0
	var lastResult *PingResult
	for n, r := range resultsSorted {

		if r.Success {
			sumRTT += r.RountripTime
			sumRTT2 += r.RountripTime * r.RountripTime
		}

		w := W(n, len(results))
		if w > 0 {
			// After and Before avearages
			aavg := float32(a) / float32(len(results)-n)
			bavg := float32(b) / float32(n)
			cavg := aavg - bavg
			if cavg < 0 {
				cavg = -cavg
			}
			score := cavg * w

			// bo := " F"
			// if r.Success {
			// 	bo = "T "
			// }

			// if n < 60 {
			// 	fmt.Printf("Debug: %6d %-58v %s %6d=%6.2f %6d=%6.2f %6.2f %6.2f %6.2f\n", n, r.Timestamp, bo, a, aavg, b, bavg, cavg, w, score)
			// }
			// fmt.Println("Debug:", n, a, aavg, b, bavg, cavg, w, score)

			if score > maxScore {
				maxScore = score
				maxIndex = n
				bestRTT = sumRTT
				bestLoss = b
				lastResult = r
			}
		}
		if r.Success {
			a -= 1
			b += 1
		}
	}
	// fmt.Println(maxIndex, len(resultsSorted))

	if maxIndex == len(resultsSorted) {
		bestLoss = b
		bestRTT = sumRTT
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

	// fmt.Println(limit, maxIndex, maxScore, bestRTT)
	probeLoss.WithLabelValues(labels...).Set(1.0 - float64(bestLoss)/(float64(maxIndex)))
	probeSamples.WithLabelValues(labels...).Set(float64(maxIndex))
	probeLatency.WithLabelValues(labels...).Set(float64(bestRTT) / (float64(bestLoss * 1000000.0)))

	// jobMap.Range(func(key any, value any) bool {
	// 	if job, ok := value.(*PingJob); ok {
	// 		job.Mutex.Lock()
	// 		probeSentCount.WithLabelValues(labels...).Add(float64(job.Sent_Count))
	// 		probeRecvCount.WithLabelValues(labels...).Add(float64(job.Recv_Count))
	// 		job.Mutex.Unlock()
	// 	}
	// 	return true
	// })

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func GetJob(ip net.IP) (*PingJob, bool) {
	var j [16]byte
	ip = ip.To16()
	copy(j[:], ip[:])
	now := time.Now()
	if temp, ok := jobMap.Load(j); ok {
		val := temp.(*PingJob)
		val.Mutex.Lock()
		val.LastAccess = now
		val.Mutex.Unlock()
		return val, false
	} else {
		new := &PingJob{IPAddress: j[:], Results: NewDataBuff[PingResult](250), LastAccess: now}
		temp, _ := jobMap.LoadOrStore(j, new)
		val := temp.(*PingJob)
		if val == new {
			signal.Signal()
		} else {
			val.Mutex.Lock()
			val.LastAccess = now
			val.Mutex.Unlock()
		}
		return val, val == new
	}
}

func PruneMap() {
	for {
		time.Sleep(1 * time.Second)
		expire := time.Now().Add(time.Duration(-10 * 60 * time.Second))
		doRebuild := false
		jobMap.Range(func(key any, value any) bool {
			if job, ok := value.(*PingJob); ok {
				// fmt.Println(key, expire.After(job.LastAccess), expire.Sub(job.LastAccess))
				remove := false
				job.Mutex.Lock()
				if expire.After(job.LastAccess) {
					remove = true
				}
				job.Mutex.Unlock()
				if remove {
					jobMap.Delete(key)
					doRebuild = true
				}
			}
			return true
		})
		if doRebuild {
			signal.Signal()
		}
	}
}
