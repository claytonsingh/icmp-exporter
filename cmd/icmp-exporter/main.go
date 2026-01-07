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
	"github.com/claytonsingh/icmp-exporter/netprobe"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

var versionString = "unknown"
var probeMap = sync.Map{}

var signal = syncsignal.NewSignal()
var resolver = nett.CacheResolver{TTL: 5 * time.Minute}

type Settings struct {
	iface4      string
	iface6      string
	useHardware bool
	listenAddr  string
	timeout     int
	interval    int
	maxpps      int
	identifier  int
}

func parseArguments() Settings {
	var errors []string
	var settings Settings
	defaults := Settings{
		iface4:      "auto",
		iface6:      "auto",
		useHardware: false,
		listenAddr:  ":9116",
		timeout:     2000,
		interval:    2000,
		maxpps:      10000,
		identifier:  0,
	}

	iWillBeGood := flag.Bool("i-wont-be-evil", false, "Unlocks advanced settings.")
	flag.StringVar(&settings.iface4, "interface4", defaults.iface4, "IPv4 interface to bind to. If \"auto\" then the default route is used.")
	flag.StringVar(&settings.iface6, "interface6", defaults.iface6, "IPv6 interface to bind to. If \"auto\" then the default route is used.")
	flag.BoolVar(&settings.useHardware, "hard", defaults.useHardware, "Use hardware timestamping.")
	flag.BoolFunc("drop", "deprecated", func(s string) error { return nil })
	flag.StringVar(&settings.listenAddr, "listen", defaults.listenAddr, "Ip and port to listen on.")
	flag.IntVar(&settings.timeout, "timeout", defaults.timeout, "ICMP / TCP timeout in milliseconds.")
	flag.IntVar(&settings.interval, "interval", defaults.interval, "ICMP / TCP interval in milliseconds. Minimum 10. Must be unlocked.")
	flag.IntVar(&settings.maxpps, "maxpps", defaults.maxpps, "Maximum packets per second. Minimum 1. Must be unlocked.")
	flag.IntVar(&settings.identifier, "identifier", defaults.identifier, "ICMP identifier between 0 and 65535. Must be unlocked. The possible options are:\n0 - Process pid (default)\n1 - Random")

	flag.Parse()

	if settings.iface4 == "auto" {
		settings.iface4, _ = netprobe.GetDefaultRouterInterface4()
	}
	if settings.iface6 == "auto" {
		settings.iface6, _ = netprobe.GetDefaultRouterInterface6()
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

	p := netprobe.NewNative(settings.useHardware, settings.iface4, settings.iface6, settings.timeout, settings.interval, settings.maxpps, settings.identifier, 61000, 65500)
	RegisterPingerMetrics(p)
	p.Start()
	go UpdateProbesThread(p)

	go PruneMapThread()

	ln, err := net.Listen("tcp", settings.listenAddr)
	if err != nil {
		panic(err)
	}

	// Drop capabilities after binding
	{
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
	mux.Handle("/debug/probes", http.HandlerFunc(DebugProbesHandler))
	if err := http.Serve(ln, PromtheusMiddlewareHandler(mux)); err != nil {
		panic(err)
	}
}

func GetProbe(ip net.IP, tcpPort uint16) (*netprobe.PingProbe, bool) {
	var ipBytes [18]byte
	ip = ip.To16()
	copy(ipBytes[:16], ip[:])
	ipBytes[16] = byte(tcpPort >> 8)
	ipBytes[17] = byte(tcpPort & 0xFF)
	now := time.Now()

	// Create a unique key that includes both IP and TCP port
	if untyped, ok := probeMap.Load(ipBytes); ok {
		probe := untyped.(*netprobe.PingProbe)
		probe.Mutex.Lock()
		probe.LastAccess = now
		probe.Mutex.Unlock()
		return probe, false
	} else {
		new := &netprobe.PingProbe{
			IPAddress:  ipBytes[:16],
			TCPPort:    tcpPort,
			Results:    netprobe.NewDataBuff[netprobe.PingResult](250),
			LastAccess: now,
		}
		untyped, _ := probeMap.LoadOrStore(ipBytes, new)
		probe := untyped.(*netprobe.PingProbe)
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
			if probe, ok := value.(*netprobe.PingProbe); ok {

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

func UpdateProbesThread(p netprobe.Pinger) {
	for wait := signal.GetWaiter(true); wait(); {
		probes := make([]*netprobe.PingProbe, 0)
		probeMap.Range(func(key any, value any) bool {
			if probe, ok := value.(*netprobe.PingProbe); ok {
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
