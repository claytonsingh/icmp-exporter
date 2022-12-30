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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PingJob struct {
	IPAddress       net.IP
	Sent_Count      int32
	Recv_Count      int32
	Roundtrip_Total int64 // In microseconds
	Results         PDB
	LastAccess      time.Time
	Mutex           sync.Mutex
}

func (this *PingJob) AddSample(sample PingResult) {
	this.Mutex.Lock()
	this.Sent_Count += 1
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
		Name: "probe_latency_total",
		Help: "",
	}, []string{"ip"})
	registry.MustRegister(probeLatencyTotal)

	probeLatency := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_latency_seconds",
		Help: "",
	}, []string{"ip"})
	registry.MustRegister(probeLatency)

	job, new := GetJob(requestIp)
	if new {
		signal.Signal()
	}

	var latency int64
	job.Mutex.Lock()
	probeSentCount.WithLabelValues(job.IPAddress.String()).Add(float64(job.Sent_Count))
	probeRecvCount.WithLabelValues(job.IPAddress.String()).Add(float64(job.Recv_Count))
	probeLatencyTotal.WithLabelValues(job.IPAddress.String()).Add(float64(job.Roundtrip_Total) / 1000000.0)
	results := job.Results.Snapshot()
	job.Mutex.Unlock()
	for _, r := range results {
		latency += r.RountripTime
	}
	probeLatency.WithLabelValues(job.IPAddress.String()).Set(float64(latency) / (float64(len(results) * 1000000.0)))

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
		new := &PingJob{IPAddress: j[:], Results: NewDataBuff[PingResult](10), LastAccess: now}
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
