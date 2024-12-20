package main

import (
	"bytes"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/abursavich/nett"
	"github.com/claytonsingh/golib/syncsignal"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type PingProbe struct {
	IPAddress        net.IP
	SentCount        int32
	RecvCount        int32
	RoundtripTotal   int64 // In microseconds
	RoundtripSqTotal int64 // In microseconds
	Results          DataBuff[PingResult]
	ResultLimit      int
	LastAccess       time.Time
	Mutex            sync.Mutex
}

func (this *PingProbe) AddSample(sample PingResult) {
	this.Mutex.Lock()

	// if we have sent many packets then reset all the counters to prevent loss of precision
	if this.SentCount >= 0x7F000000 {
		this.SentCount = 0
		this.RecvCount = 0
		this.RoundtripTotal = 0
		this.RoundtripSqTotal = 0
	}

	this.SentCount += 1
	this.ResultLimit += 1
	if this.ResultLimit > this.Results.Size {
		this.ResultLimit = this.Results.Size
	}

	this.Results.Append(sample)
	if sample.Success {
		this.RecvCount += 1
		this.RoundtripTotal += sample.RountripTime
		this.RoundtripSqTotal += sample.RountripTime * sample.RountripTime
	}
	this.Mutex.Unlock()
}

type PingResult struct {
	Success      bool
	RountripTime int64 // In microseconds
	Timestamp    time.Time
}

var versionString = "unknown"
var probeMap = sync.Map{}

var signal = syncsignal.NewSignal()
var resolver = nett.CacheResolver{TTL: 5 * time.Minute}

type Settings struct {
	iface4           string
	iface6           string
	useHardware      bool
	listenAddr       string
	timeout          int
	interval         int
	maxpps           int
	dropCapabilities bool
	identifier       int
}

func parseArguments() Settings {
	var errors []string
	var settings Settings
	defaults := Settings{
		iface4:           "auto",
		iface6:           "auto",
		useHardware:      false,
		listenAddr:       ":9116",
		timeout:          3000,
		interval:         2000,
		maxpps:           10000,
		dropCapabilities: false,
		identifier:       0,
	}

	iWillBeGood := flag.Bool("i-wont-be-evil", false, "Unlocks advanced settings.")
	flag.StringVar(&settings.iface4, "interface4", defaults.iface4, "IPv4 interface to bind to. If \"auto\" then the default route is used.")
	flag.StringVar(&settings.iface6, "interface6", defaults.iface6, "IPv6 interface to bind to. If \"auto\" then the default route is used.")
	flag.BoolVar(&settings.useHardware, "hard", defaults.useHardware, "Use hardware timestamping.")
	flag.BoolVar(&settings.dropCapabilities, "drop", defaults.dropCapabilities, "Drop capabilities after starting.")
	flag.StringVar(&settings.listenAddr, "listen", defaults.listenAddr, "Ip and port to listen on.")
	flag.IntVar(&settings.timeout, "timeout", defaults.timeout, "ICMP timout in milliseconds.")
	flag.IntVar(&settings.interval, "interval", defaults.interval, "ICMP interval in milliseconds. Minimum 10. Must be unlocked.")
	flag.IntVar(&settings.maxpps, "maxpps", defaults.maxpps, "Maximum packets per second. Minimum 1. Must be unlocked.")
	flag.IntVar(&settings.identifier, "identifier", defaults.identifier, "ICMP identifier between 0 and 65535. Must be unlocked. The possible options are:\n0 - Process pid (default)\n1 - Random")
	flag.Parse()

	if settings.iface4 == "auto" {
		settings.iface4, _ = GetDefaultRouterInterface4()
	}
	if settings.iface6 == "auto" {
		settings.iface6, _ = GetDefaultRouterInterface6()
	}

	if settings.iface4 != "" {
		log.Println("trying to bind ipv4 to: " + settings.iface4)
	} else {
		log.Println("ipv4 disabled; maybe set interface4?")
	}
	if settings.iface6 != "" {
		log.Println("trying to bind ipv6 to: " + settings.iface6)
	} else {
		log.Println("ipv6 disabled; maybe set interface6?")
	}

	if settings.iface4 == "" && settings.iface6 == "" {
		errors = append(errors, "interface4 and interface6 is not set")
	}

	if *iWillBeGood {
		if settings.timeout < 10 {
			errors = append(errors, "timeout must be 10 or more")
		}
		if (settings.maxpps < 1) || (settings.maxpps > 1000000) {
			errors = append(errors, "maxpps must be between 1 and 1000000")
		}
		if (settings.identifier < 0) || (settings.identifier > 65535) {
			errors = append(errors, "identifier must be between 0 and 65535")
		}
	} else {
		settings.timeout = defaults.timeout
		settings.maxpps = defaults.maxpps
		settings.identifier = defaults.identifier
	}

	if errors != nil {
		for _, e := range errors {
			log.Println("ERROR:", e)
		}
		os.Exit(1)
	}

	return settings
}

func main() {
	log.Println("icmp-exporter version: ", versionString)
	settings := parseArguments()

	p := NewICMPNative(settings.useHardware, settings.iface4, settings.iface6, settings.timeout, settings.interval, settings.maxpps, (uint16)(settings.identifier))
	p.Start()

	go UpdateProbesThread(p)
	go PruneMapThread()

	ln, err := net.Listen("tcp", settings.listenAddr)
	if err != nil {
		panic(err)
	}

	// Drop capabilities after binding
	if settings.dropCapabilities {
		// Read and display the capabilities of the running process
		c := cap.GetProc()
		log.Println("process started with caps:", c)

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

		log.Println("successfully dropped all caps")
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}))
	mux.Handle("/probe", http.HandlerFunc(ProbeHander))
	if err := http.Serve(ln, PromtheusMiddlewareHandler(mux)); err != nil {
		panic(err)
	}
}

func GetProbe(ip net.IP) (*PingProbe, bool) {
	var ipBytes [16]byte
	ip = ip.To16()
	copy(ipBytes[:], ip[:])
	now := time.Now()
	if untyped, ok := probeMap.Load(ipBytes); ok {
		probe := untyped.(*PingProbe)
		probe.Mutex.Lock()
		probe.LastAccess = now
		probe.Mutex.Unlock()
		return probe, false
	} else {
		new := &PingProbe{IPAddress: ipBytes[:], Results: NewDataBuff[PingResult](250), LastAccess: now}
		untyped, _ := probeMap.LoadOrStore(ipBytes, new)
		probe := untyped.(*PingProbe)
		if probe == new {
			signal.Signal()
		} else {
			probe.Mutex.Lock()
			probe.LastAccess = now
			probe.Mutex.Unlock()
		}
		return probe, probe == new
	}
}

// PruneMapThread cleans out old jobs
func PruneMapThread() {
	for {
		time.Sleep(1 * time.Second)
		expire := time.Now().Add(time.Duration(-10 * 60 * time.Second))
		doRebuild := false
		probeMap.Range(func(key any, value any) bool {
			if probe, ok := value.(*PingProbe); ok {

				remove := false
				probe.Mutex.Lock()
				if expire.After(probe.LastAccess) {
					remove = true
				}
				probe.Mutex.Unlock()
				if remove {
					probeMap.Delete(key)
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

func UpdateProbesThread(p *ICMPNative) {
	Wait := signal.GetWaiter(true)
	for {
		Wait()
		probes := make([]*PingProbe, 0)
		probeMap.Range(func(key any, value any) bool {
			if probe, ok := value.(*PingProbe); ok {
				probes = append(probes, probe)
			}
			return true
		})
		sort.Slice(probes, func(i int, j int) bool {
			return bytes.Compare(probes[i].IPAddress, probes[j].IPAddress) < 0
		})
		p.SetProbes(probes)
		time.Sleep(1 * time.Second)
	}
}
