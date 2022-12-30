package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
	//"github.com/ReneKroon/ttlcache"
)

type PingJob struct {
	//SequenceNumber uint16
	//IPAddress      syscall.SockaddrInet4
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

// func GetOrAdd(this map[[16]byte]*PingJob, ip net.IP) (*PingJob, bool) {
// 	var j [16]byte
// 	ip = ip.To16()
// 	copy(j[:], ip[:])
// 	if val, ok := this[j]; ok {
// 		return val, false
// 	} else {
// 		Job := &PingJob{IPAddress: ip, Results: NewDataBuff[PingResult](10)}
// 		this[j] = Job
// 		return Job, true
// 	}
// }

// func Values[M ~map[K]V, K comparable, V any](m M) []V {
//     r := make([]V, 0, len(m))
//     for _, v := range m {
//         r = append(r, v)
//     }
//     return r
// }

func main() {

	iface := flag.String("interface", "", "Interface to bind to")
	use_hardware := flag.Bool("hard", false, "Use hardware timestamping")
	listen_addr := flag.String("listen", ":9116", "ip and port to listen on, defaults to :9116")
	flag.Parse()

	// main2()

	// var p ICMPNative
	p := NewICMPNative(*use_hardware, *iface)
	p.Start()

	//m := make(map[[16]byte]*PingJob)

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
			// for i := range r {
			// 	fmt.Print(r[i].IPAddress)
			// 	fmt.Print(" ")
			// 	if i%10 == 9 {
			// 		fmt.Print("\n")
			// 	}
			// }
			// fmt.Print("\n")

			fmt.Println("Updated Job List", len(r))
			// fmt.Println("q", r)
			p.SetJobs(r)
			// time.Sleep(1 * time.Second)
		}
	}()
	go PruneMap()

	if _, new := GetJob(net.IPv4(10, 10, 0, 1)); new {
		signal.Signal()
	}

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", ProbeHander)
	http.ListenAndServe(*listen_addr, nil)

	// srv := &http.Server{}
	// flags := web.FlagConfig{WebListenAddresses: &[]string{":9116"}}
	// promlogConfig := &promlog.Config{}
	// logger := promlog.New(promlogConfig)
	// web.ListenAndServe(srv, &flags, logger)

	// for {
	// 	time.Sleep(1 * time.Second)
	// 	p.m_job_mutex.Lock()
	// 	for idx := range p.m_jobs {
	// 		fmt.Println(&p.m_jobs[idx], p.m_jobs[idx])
	// 	}
	// 	p.m_job_mutex.Unlock()
	// }
	// time.Sleep(1 * time.Second)
	// GetJob(net.IPv4(10, 10, 0, 1))
	// //jobMap.Store("A", qq)
	// signal.Signal()

	// time.Sleep(6 * time.Second)
	// if _, new := GetJob(net.IPv4(10, 10, 0, 1)); new {
	// 	signal.Signal()
	// 	//p.SetJobs(Values(m))
	// }

	// time.Sleep(10 * time.Second)
	// if _, new := GetJob(net.IPv4(173, 255, 215, 60)); new {
	// 	signal.Signal()
	// 	//p.SetJobs(Values(m))
	// }

	// time.Sleep(10 * time.Second)
	// if _, new := GetJob(net.IPv4(44, 31, 185, 60)); new {
	// 	signal.Signal()
	// 	//p.SetJobs(Values(m))
	// }

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

func main2() {

	pkt := IcmpPacket{
		Type:           8,
		Code:           0,
		Identifier:     1,
		SequenceNumber: 2,
		Payload: []byte{
			00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
		},
	}
	buf := make([]byte, 2048)
	//fmt.Printf("% X\n", buf[:n])

	fmt.Println("Hello World !!")

	flags := unix.SOF_TIMESTAMPING_RX_HARDWARE | unix.SOF_TIMESTAMPING_TX_HARDWARE | unix.SOF_TIMESTAMPING_RAW_HARDWARE

	// fd := socket_create()
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err := socket_set_ioctl(fd, "ens16", flags); err != nil {
		panic(err)
	}
	socket_set_flags(fd, flags, 0, 0)

	recvpacket2(fd)

	time.Sleep(2 * time.Second)

	for true {
		pkt.SequenceNumber++
		n := pkt.Serialize(buf)
		addr := syscall.SockaddrInet4{Addr: [4]byte{10, 10, 0, 1}}
		// x := syscall.SockaddrInet6{Addr: [16]byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}
		syscall.Sendto(fd, buf[:n], 0, &addr)

		time.Sleep(1 * time.Second)
	}
	//select {}

	// http.Handle("/metrics", promhttp.Handler())
	// http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
	// 	w.WriteHeader(http.StatusOK)
	// 	w.Write([]byte("Healthy"))
	// })
	// http.ListenAndServe(":2112", nil)
}

// func recvpacket() {
// 	protocol := "icmp"
// 	netaddr, _ := net.ResolveIPAddr("ip4", "127.0.0.1")
// 	conn, _ := net.ListenIP("ip4:"+protocol, netaddr)

// 	buf := make([]byte, 1024)
// 	numRead, _, _ := conn.ReadFrom(buf)

// 	fmt.Printf("% X\n", buf[:numRead])
// }
// func recvpacket3(fd int, data []byte, flags int) (n int, err error) {
// 	oob := make([]byte, 1024)
// 	n, noob, _, _, err := syscall.Recvmsg(fd, data, oob, flags)
// 	if err != nil {
// 		return
// 	}

// 	msgs, _ := unix.ParseSocketControlMessage(oob[:noob])
// 	for _, msg := range msgs {
// 		if msg.Header.Type == unix.SOL_SOCKET && msg.Header.Level == unix.SO_TIMESTAMPING {

// 		}
// 		fmt.Printf("tx msg: %v %v\n", msg.Header.Type, msg.Header.Level)
// 	}

// 	fmt.Printf("tx msg: %v\n", len(msgs))
// 	return
// }

func recvpacket2(fd int) {
	// go func() {
	// 	data := make([]byte, syscall.Getpagesize())
	// 	oob := make([]byte, syscall.Getpagesize())
	// 	for true {
	// 		if ndata, noob, _, _, err := syscall.Recvmsg(fd, data, oob, 0); err != nil {
	// 			panic(err)
	// 		} else {
	// 			fmt.Printf("rx data: %v - % X\n", ndata, data[:ndata])
	// 			fmt.Printf("rx oob:  %v - % X\n", noob, oob[:noob])
	// 		}
	// 	}
	// }()

	// go func() {
	// 	data := make([]byte, syscall.Getpagesize())
	// 	oob := make([]byte, syscall.Getpagesize())
	// 	for true {
	// 		// var addr uint32
	// 		// var n_seconds int64
	// 		// ndata := recvpacket(fd, data, &addr, &n_seconds, unix.MSG_ERRQUEUE)
	// 		// // ndata := C.recvpacket(C.int32_t(fd), (*C.uint8_t)(unsafe.Pointer(&data[0])), C.uint32_t(len(data)), (*C.uint32_t)(unsafe.Pointer(&addr)), (*C.int64_t)(unsafe.Pointer(&n_seconds)), unix.MSG_ERRQUEUE)
	// 		// //ndata := C.recvpacket(C.int32_t(fd), (*C.uint8_t)(unsafe.Pointer(&data[0])), C.uint32_t(len(data)), (*C.uint32_t)(unsafe.Pointer(&addr)), unix.MSG_ERRQUEUE)

	// 		// if ndata >= 0 {
	// 		// 	fmt.Printf("tx data: %v - % X\n", ndata, data[:ndata])
	// 		// } else {
	// 		// 	fmt.Printf("tx data: %v\n", ndata)
	// 		// }

	// 		ndata, noob, _, _, err := syscall.Recvmsg(fd, data, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	// 		if err == syscall.EAGAIN {
	// 			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLERR}}
	// 			unix.Poll(fds, 1100)
	// 			fmt.Printf("tx poll: %v %v\n", fds[0].Events, fds[0].Revents)
	// 			continue
	// 		} else if err != nil {
	// 			//if ndata, noob, _, err := recvmsgRaw(fd, data, oob, unix.MSG_ERRQUEUE, &rsa); err != nil {
	// 			panic(err)
	// 		} else {
	// 			fmt.Printf("tx data: %v - % X\n", ndata, data[:ndata])
	// 			fmt.Printf("tx oob:  %v - % X\n", noob, oob[:noob])

	// 			msgs, _ := unix.ParseSocketControlMessage(oob[:noob])
	// 			fmt.Printf("tx msg: %v\n", len(msgs))

	// 			fmt.Printf("tx xxx: %v %v\n", unix.SO_TIMESTAMPING, unix.SOL_SOCKET)
	// 			for _, msg := range msgs {
	// 				// if msg.Header.Level == unix.SOL_SOCKET && msg.Header.Type == unix.SO_TIMESTAMPING {
	// 				// 	fmt.Printf("tx msg: %v - % X\n", len(msg.Data), msg.Data)

	// 				// }
	// 				fmt.Printf("tx msg: %v - % X\n", len(msg.Data), msg.Data)
	// 			}
	// 		}
	// 	}
	// }()

	go func() {
		data := make([]byte, syscall.Getpagesize())
		for true {
			ndata, ts := recvpacket_v4(fd, data, 0, unix.SO_TIMESTAMPING)
			if ndata < 0 {
				panic(ndata)
			} else {
				fmt.Printf("rx data: %v - % X\n", ndata, data[:ndata])
				fmt.Printf("rx msg:  %v\n", ts)

				//var eth layers.Ethernet
				var ip4 layers.IPv4
				var ic4 layers.ICMPv4

				parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &ic4)
				parser.IgnoreUnsupported = true
				decoded := []gopacket.LayerType{}
				if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
					for _, layerType := range decoded {
						switch layerType {
						// case layers.LayerTypeIPv6:
						// 	fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
						case layers.LayerTypeIPv4:
							fmt.Println("rx IP4: ", ip4.SrcIP, ip4.DstIP)
						case layers.LayerTypeICMPv4:
							fmt.Println("rx IC4: ", ic4.Seq, ic4.Payload)
						}
					}
				} else {
					fmt.Println("err ", err)
				}
			}
		}
	}()

	go func() {
		data := make([]byte, syscall.Getpagesize())
		for true {
			ndata, ts := recvpacket_v4(fd, data, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT, unix.SO_TIMESTAMPING)
			if ndata == -1 {
				fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLERR}}
				unix.Poll(fds, 1100)
				//fmt.Printf("tx poll: %v %v\n", fds[0].Events, fds[0].Revents)
				continue
			} else if ndata < 0 {
				panic(ndata)
			} else {
				// ihl := (data[0] & 0x0F) * 4
				fmt.Printf("tx data: %v - % X\n", ndata, data[14:ndata])
				fmt.Printf("tx msg:  %v\n", ts)

				var eth layers.Ethernet
				var ip4 layers.IPv4
				var ic4 layers.ICMPv4

				parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ic4)
				parser.IgnoreUnsupported = true
				decoded := []gopacket.LayerType{}
				if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
					for _, layerType := range decoded {
						switch layerType {
						// case layers.LayerTypeIPv6:
						// 	fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
						case layers.LayerTypeIPv4:
							fmt.Println("tx IP4: ", ip4.SrcIP, ip4.DstIP)
						case layers.LayerTypeICMPv4:
							fmt.Println("tx IC4: ", ic4.Seq, ic4.Payload)
						}
					}
				} else {
					fmt.Println("err ", err)
				}

				// packet := gopacket.NewPacket(data[14:ndata], layers.LayerTypeIPv4, gopacket.Default)
				// if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				// 	ipv4 := ipv4Layer.(*layers.IPv4)

				// 	fmt.Printf("tx msg:  %v %v %v\n", ipv4.DstIP, ipv4.SrcIP, ipv4.Payload)
				// }
			}
		}
	}()
}

type ifreq struct {
	ifr_name [16]byte
	ifr_data hwtstamp_config
	_        [12]byte
}

type hwtstamp_config struct {
	flags     int32
	tx_type   int32
	rx_filter int32
}

func recvmsgRaw(fd int, p, oob []byte, flags int, rsa *syscall.RawSockaddrAny) (n, oobn int, recvflags int, err error) {
	var msg syscall.Msghdr
	msg.Name = (*byte)(unsafe.Pointer(rsa))
	msg.Namelen = uint32(syscall.SizeofSockaddrAny)
	var iov syscall.Iovec
	if len(p) > 0 {
		iov.Base = &p[0]
		iov.SetLen(len(p))
	}
	var dummy byte
	if len(oob) > 0 {
		if len(p) == 0 {
			var sockType int
			sockType, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
			if err != nil {
				return
			}
			// receive at least one normal byte
			if sockType != syscall.SOCK_DGRAM {
				iov.Base = &dummy
				iov.SetLen(1)
			}
		}
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	msg.Iov = &iov
	msg.Iovlen = 1
	if n, err = recvmsg(fd, &msg, flags); err != nil {
		return
	}
	oobn = int(msg.Controllen)
	recvflags = int(msg.Flags)
	return
}

func recvmsg(s int, msg *syscall.Msghdr, flags int) (n int, err error) {
	//fmt.Printf("recvmsg: %v %v %v\n", s, msg, flags)
	r0, _, e1 := syscall.Syscall(syscall.SYS_RECVMSG, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	//fmt.Printf("recvmsg: %v %v %v\n", int(r0), int(r1), e1)

	n = int(r0)
	if e1 != 0 {
		err = e1
	}
	return
}
