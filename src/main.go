package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/abursavich/nett"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type PingJob struct {
	IPAddress          net.IP
	Sent_Count         int32
	Recv_Count         int32
	Roundtrip_Total    int64 // In microseconds
	Roundtrip_Sq_Total int64 // In microseconds
	Results            PDB
	ResultLimit        int
	LastAccess         time.Time
	Mutex              sync.Mutex
}

func (this *PingJob) AddSample(sample PingResult) {
	this.Mutex.Lock()

	// if we have recieved many packets then reset all the counters to prevent loss of percision
	if this.Recv_Count >= 0x7F000000 {
		this.Sent_Count = 0
		this.Recv_Count = 0
		this.Roundtrip_Total = 0
		this.Roundtrip_Sq_Total = 0
	}

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
		this.Roundtrip_Sq_Total += sample.RountripTime * sample.RountripTime
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

type Settings struct {
	iface4            string
	iface6            string
	use_hardware      bool
	listen_addr       string
	timeout           int
	interval          int
	max_pps           int
	drop_capabilities bool
}

func parseArguments() Settings {
	var errors []string
	var settings Settings
	defaults := Settings{
		iface4:            "auto",
		iface6:            "auto",
		use_hardware:      false,
		listen_addr:       ":9116",
		timeout:           3000,
		interval:          2000,
		max_pps:           10000,
		drop_capabilities: false,
	}

	i_will_be_good := flag.Bool("i-wont-be-evil", false, "Unlocks all other settings")
	flag.StringVar(&settings.iface4, "interface4", defaults.iface4, "IPv4 interface to bind to.")
	flag.StringVar(&settings.iface6, "interface6", defaults.iface6, "IPv6 interface to bind to.")
	flag.BoolVar(&settings.use_hardware, "hard", defaults.use_hardware, "Use hardware timestamping.")
	flag.BoolVar(&settings.drop_capabilities, "drop", defaults.drop_capabilities, "Drop capabilities after starting.")
	flag.StringVar(&settings.listen_addr, "listen", defaults.listen_addr, "ip and port to listen on.")
	flag.IntVar(&settings.timeout, "timeout", defaults.timeout, "Timout in milliseconds.")
	flag.IntVar(&settings.interval, "interval", defaults.interval, "Interval in milliseconds. Minimum 10. Must be unlocked.")
	flag.IntVar(&settings.max_pps, "maxpps", defaults.max_pps, "Maximum packets per second. Minimum 1. Must be unlocked.")
	flag.Parse()

	if settings.iface4 == "auto" {
		settings.iface4, _ = GetDefaultRouterInterface4()
	}
	if settings.iface6 == "auto" {
		settings.iface6, _ = GetDefaultRouterInterface6()
	}

	if settings.iface4 != "" {
		fmt.Println("trying to bind ipv4 to: " + settings.iface4)
	} else {
		fmt.Println("ipv4 disabled; maybe set interface4?")
	}
	if settings.iface6 != "" {
		fmt.Println("trying to bind ipv6 to: " + settings.iface6)
	} else {
		fmt.Println("ipv6 disabled; maybe set interface6?")
	}

	if settings.iface4 == "" && settings.iface6 == "" {
		errors = append(errors, "interface4 and interface6 is not set")
	}

	if *i_will_be_good {
		if settings.timeout < 10 {
			errors = append(errors, "timeout must be greater then 9")
		}
		if settings.max_pps < 1 {
			errors = append(errors, "max_pps must be greater then 0")
		}
		if settings.max_pps > 1000000 {
			errors = append(errors, "max_pps must be less then 1000001")
		}
	} else {
		settings.timeout = defaults.timeout
		settings.max_pps = defaults.max_pps
	}

	if errors != nil {
		for _, e := range errors {
			fmt.Println("ERROR:", e)
		}
		os.Exit(1)
	}

	return settings
}

func main() {
	settings := parseArguments()

	p := NewICMPNative(settings.use_hardware, settings.iface4, settings.iface6, settings.timeout, settings.interval, settings.max_pps)
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

	ln, err := net.Listen("tcp", settings.listen_addr)
	if err != nil {
		panic(err)
	}

	// Drop capabilities after binding
	if settings.drop_capabilities {
		// Read and display the capabilities of the running process
		c := cap.GetProc()
		log.Println("this process has these caps:", c)

		// Drop any privilege a process might have (including for root,
		// but note root 'owns' a lot of system files so a cap-limited
		// root can still do considerable damage to a running system).
		old := cap.GetProc()
		empty := cap.NewSet()
		if err := empty.SetProc(); err != nil {
			log.Fatalf("failed to drop privilege: %q -> %q: %v", old, empty, err)
		}
		now := cap.GetProc()
		if cf, _ := now.Cf(empty); cf != 0 {
			log.Fatalf("failed to fully drop privilege: have=%q, wanted=%q", now, empty)
		}
	}

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", ProbeHander)
	http.Serve(ln, nil)

	// select {}
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
