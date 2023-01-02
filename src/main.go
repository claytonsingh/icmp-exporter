package main

import (
	"bytes"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

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

	if _, new := GetJob(net.IPv4(10, 10, 0, 1)); new {
		signal.Signal()
	}

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", ProbeHander)
	http.ListenAndServe(*listen_addr, nil)

	select {}
}

func Max32(a float32, b float32) float32 {
	if a > b {
		return a
	}
	return b
}

func W(n int, l int) float32 {
	nf := float64(n)
	lf := float64(l)
	p := 1.4
	return float32(math.Max(1-math.Pow(25, p)/math.Pow(nf, p), 0) * math.Max(1-math.Pow(25, p)/math.Pow(lf-nf, p), 0))
	//return Max32(1.0-(25*25)/(nf*nf), 0) * Max32(1-(25*25)/((lf-nf)*(lf-nf)), 0)
}

func ProbeHander(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	requestIp := net.ParseIP(params.Get("ip"))
	if requestIp == nil {
		return
	}

	registry := prometheus.NewRegistry()

	probeSentCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "probe_sent_count",
		Help: "How many icmp packets were sent to the target ip",
	}, []string{"ip"})
	registry.MustRegister(probeSentCount)

	probeRecvCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "probe_recv_count",
		Help: "How many icmp packets were recieved from the target ip",
	}, []string{"ip"})
	registry.MustRegister(probeRecvCount)

	probeLatencyTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "probe_latency_seconds_total",
		Help: "",
	}, []string{"ip"})
	registry.MustRegister(probeLatencyTotal)

	probeLatency := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_latency_seconds",
		Help: "",
	}, []string{"ip"})
	registry.MustRegister(probeLatency)

	probeLoss := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_loss_ratio",
		Help: "",
	}, []string{"ip"})
	registry.MustRegister(probeLoss)

	probeSamples := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_samples_count",
		Help: "",
	}, []string{"ip"})
	registry.MustRegister(probeSamples)

	job, new := GetJob(requestIp)
	if new {
		signal.Signal()
	}

	resultsSorted := make([]*PingResult, 0, job.Results.Size)
	job.Mutex.Lock()
	probeSentCount.WithLabelValues(job.IPAddress.String()).Add(float64(job.Sent_Count))
	probeRecvCount.WithLabelValues(job.IPAddress.String()).Add(float64(job.Recv_Count))
	probeLatencyTotal.WithLabelValues(job.IPAddress.String()).Add(float64(job.Roundtrip_Total) / 1000000.0)

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

	var limit int = len(resultsSorted) - 25
	if len(resultsSorted) < 50 {
		limit = len(resultsSorted)
	} else if len(resultsSorted) < 75 {
		limit = 50
	}
	var maxScore float32 = 0.12
	var maxIndex int = limit
	var sumRTT int64 = 0
	var sumRTT2 int64 = 0
	var bestRTT int64 = 0
	var bestLoss int = 0
	var lastResult *PingResult
	for n, r := range resultsSorted {
		if n == limit {
			break
		}

		// r := &results[len(results)-n-1]

		// After and Before avearages
		aavg := float32(a) / float32(len(results)-n)
		bavg := float32(b) / float32(n)

		cavg := aavg - bavg
		if cavg < 0 {
			cavg = 0 - cavg
		}
		w := W(n, len(results))
		score := cavg * w

		if r.Success {
			sumRTT += r.RountripTime
			sumRTT2 += r.RountripTime * r.RountripTime
		}

		// bo := " F"
		// if r.Success {
		// 	bo = "T "
		// }

		// fmt.Printf("Debug: %6d %-58v %s %6d=%6.2f %6d=%6.2f %6.2f %6.2f %6.2f\n", n, r.Timestamp, bo, a, aavg, b, bavg, cavg, w, score)
		// fmt.Println("Debug:", n, a, aavg, b, bavg, cavg, w, score)

		if score > maxScore {
			maxScore = score
			maxIndex = n
			bestRTT = sumRTT
			bestLoss = b
			lastResult = r
		}

		if r.Success {
			a -= 1
			b += 1
		}
	}

	if maxIndex == limit {
		bestLoss = b
		bestRTT = sumRTT
	}
	if lastResult != nil {
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
	probeLoss.WithLabelValues(job.IPAddress.String()).Set(1.0 - float64(bestLoss)/(float64(maxIndex)))
	probeSamples.WithLabelValues(job.IPAddress.String()).Set(float64(maxIndex))
	probeLatency.WithLabelValues(job.IPAddress.String()).Set(float64(bestRTT) / (float64(bestLoss * 1000000.0)))

	// jobMap.Range(func(key any, value any) bool {
	// 	if job, ok := value.(*PingJob); ok {
	// 		job.Mutex.Lock()
	// 		probeSentCount.WithLabelValues(job.IPAddress.String()).Add(float64(job.Sent_Count))
	// 		probeRecvCount.WithLabelValues(job.IPAddress.String()).Add(float64(job.Recv_Count))
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
