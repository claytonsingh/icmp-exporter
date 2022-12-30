package main

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"

	"github.com/elliotchance/orderedmap/v2"
)

type nativePinger struct {
	timestampStart time.Time
	timestampSend  int64
	timestampRecv  int64
	packet         IcmpPacket
	Job            *PingJob
	m_mutex        sync.Mutex
}

type ICMPNative struct {
	m_socket          int
	m_nativePinger    *orderedmap.OrderedMap[uint64, *nativePinger]
	m_jobs            []*PingJob
	m_job_mutex       sync.Mutex
	m_mutex           sync.RWMutex
	m_started         bool
	m_timeout         float32
	m_pingrate        float32
	m_identifier      uint16
	m_timestamp_type  int
	m_timestamp_flags int
	m_interface       string
}

func NewICMPNative(hardware bool, iface string) *ICMPNative {
	var this ICMPNative
	this.m_identifier = (uint16)(os.Getpid())
	this.m_nativePinger = orderedmap.NewOrderedMap[uint64, *nativePinger]()
	this.m_timeout = 3
	this.m_pingrate = 2
	this.m_interface = iface

	if hardware {
		this.m_timestamp_flags = unix.SOF_TIMESTAMPING_RX_HARDWARE | unix.SOF_TIMESTAMPING_TX_HARDWARE | unix.SOF_TIMESTAMPING_RAW_HARDWARE
		this.m_timestamp_type = 2
	} else {
		this.m_timestamp_flags = unix.SOF_TIMESTAMPING_RX_SOFTWARE | unix.SOF_TIMESTAMPING_TX_SOFTWARE | unix.SOF_TIMESTAMPING_SOFTWARE
		this.m_timestamp_type = 0
	}

	return &this
}

func (this *ICMPNative) Start() {
	if this.m_started {
		return
	}
	this.m_started = true

	if socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP); err != nil {
		panic(err)
	} else {
		this.m_socket = socket
	}

	// if err := socket_set_ioctl(this.m_socket, "ens16", flags); err != nil {
	// 	panic(err)
	// }
	if err := socket_set_ioctl_native(this.m_socket, this.m_interface, this.m_timestamp_flags); err < 0 {
		panic(err)
	}
	socket_set_flags(this.m_socket, this.m_timestamp_flags, 0, 0)

	go this.timeout_thread()
	go this.transmit_thread()
	go this.receive_thread()
	go this.error_thread()
}

func (this *ICMPNative) SetJobs(jobs []*PingJob) {
	this.m_job_mutex.Lock()
	this.m_jobs = jobs
	this.m_job_mutex.Unlock()
}

func (this *ICMPNative) addSample(pinger *nativePinger, id uint64, success bool) {
	this.m_mutex.Lock()
	this.m_nativePinger.Delete(id)
	this.m_mutex.Unlock()

	// if there was an error ont count the packet
	if pinger.timestampSend == -1 || pinger.timestampRecv == -1 {
		return
	}

	if success {
		if pinger.timestampSend < pinger.timestampRecv {
			pinger.Job.AddSample(PingResult{
				Success:      true,
				RountripTime: pinger.timestampRecv - pinger.timestampSend,
				Timestamp:    pinger.timestampStart,
			})
		}
	} else {
		pinger.Job.AddSample(PingResult{
			Success:      false,
			RountripTime: 0,
			Timestamp:    pinger.timestampStart,
		})
	}

	// pinger.Job.Mutex.Lock()
	// pinger.Job.Sent_Count += 1
	// if success {
	// 	pinger.Job.Recv_Count += 1
	// 	pinger.Job.Results.Append()
	// } else {
	// 	pinger.Job.Results.Append(PingResult{
	// 		Success:      false,
	// 		RountripTime: 0,
	// 		Timestamp:  pinger.timestampStart,
	// 	})
	// }
	// pinger.Job.Mutex.Unlock()

	// pinger.Job.Mutex.Lock()
	// var s string
	// var cnt float32
	// s += fmt.Sprintf(" %-15v", pinger.Job.IPAddress)
	// sn := pinger.Job.Results.Snapshot()
	// for _,r := range sn {
	// 	if r.Success {
	// 		s += fmt.Sprintf(" %5.2f", r.RountripTime * 1000)
	// 		cnt += 1
	// 	} else {
	// 		s += "     X"
	// 	}
	// }
	// if success {
	// 	s = "Success" + fmt.Sprintf(" %5.2f", cnt / (float32)(len(sn))) + fmt.Sprintf(" %d %d", pinger.Job.Recv_Count, pinger.Job.Sent_Count) + " " + s
	// } else {
	// 	s = "Failed " + fmt.Sprintf(" %5.2f", cnt / (float32)(len(sn))) + fmt.Sprintf("%d %d", pinger.Job.Recv_Count, pinger.Job.Sent_Count) + " " + s
	// }
	// fmt.Println(s)
	// pinger.Job.Mutex.Unlock()
}

func (this *ICMPNative) timeout_thread() {
	for {
		this.m_mutex.RLock()
		front := this.m_nativePinger.Front()
		this.m_mutex.RUnlock()
		// fmt.Println(this.m_nativePinger)
		if front == nil {
			time.Sleep(time.Duration(this.m_timeout*1000) * time.Millisecond)
		} else {
			dt := front.Value.timestampStart.Sub(time.Now()) + time.Second*time.Duration(this.m_timeout)
			// fmt.Println("DT:", dt, &front.Value.Job, front.Key, front.Value.Job.IPAddress, front.Value.Job.Sent_count)
			if dt > 0 {
				time.Sleep(dt)
			}
			front.Value.m_mutex.Lock()
			this.addSample(front.Value, front.Key, false)
			front.Value.m_mutex.Unlock()
		}
	}
}

func (this *ICMPNative) transmit_thread() {
	buf := make([]byte, 2048)
	var id uint64
	var SequenceNumber uint16
	//var last_time uint64
	for {
		this.m_job_mutex.Lock()
		jobs := this.m_jobs
		this.m_job_mutex.Unlock()
		if len(jobs) == 0 {
			time.Sleep(1 * time.Second)
		}
		for idx := range jobs {
			id = id + 1
			time.Sleep(time.Duration(this.m_pingrate*1000) * time.Millisecond / time.Duration(len(jobs)))
			var x nativePinger
			x.timestampStart = time.Now()
			x.Job = jobs[idx]
			// timestampSend  int64
			// timestampRecv  int64
			// packet         IcmpPacket
			//fmt.Println("Tx:", &x.Job, x.PacketIndex, x.Job.SequenceNumber)
			this.m_mutex.Lock()
			this.m_nativePinger.Set(id, &x)
			this.m_mutex.Unlock()

			x.packet = IcmpPacket{
				Type:           8,
				Code:           0,
				Identifier:     this.m_identifier,
				SequenceNumber: SequenceNumber,
				// Payload: []byte{
				// 	00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
				// },
				Payload: []byte("\000\000\000\000\000\000\000\000....Hello World................................."),
				//                                               ........................................................
			}

			WriteUint64(x.packet.Payload, 0, id)
			n := x.packet.Serialize(buf)
			// y := x.Job.IPAddress
			//address := syscall.SockaddrInet4{}
			//copy(address, x.Job.IPAddress[12:16])
			// var arr [4]byte
			// ii := x.Job.IPAddress

			// fmt.Println("tx A1: ", arr, ii, ii[:], x.Job.IPAddress, x.Job.IPAddress[:], x.Job.IPAddress[12], x.Job.IPAddress[13], x.Job.IPAddress[14], x.Job.IPAddress[15])
			// copy(address, ([4]byte)x.Job.IPAddress[12:])
			// fmt.Println("tx A2: ", arr, x.Job.IPAddress)
			// fmt.Println("tx A2: ", address.Addr)

			ipv4 := x.Job.IPAddress.To4()
			address := syscall.SockaddrInet4{Addr: [4]byte{ipv4[0], ipv4[1], ipv4[2], ipv4[3]}}
			// ipv16 := x.Job.IPAddress.To16()
			// address := syscall.SockaddrInet6{Addr: [16]byte{}}
			// copy(address.Addr[:], ipv16[:])
			// fmt.Printf("rx data: %v - % X \n", address, address.Addr)
			if err := syscall.Sendto(this.m_socket, buf[:n], 0, &address); err != nil {
				panic(err)
			}
		}
		SequenceNumber += 1
	}
}

func (this *ICMPNative) receive_thread() {
	data := make([]byte, syscall.Getpagesize())
	for true {
		ndata, ts := recvpacket_v4(this.m_socket, data, 0, this.m_timestamp_type)
		if ndata < 0 {
			panic(ndata)
		} else {
			//fmt.Printf("rx data: %v - % X\n", ndata, data[:ndata])
			//fmt.Printf("rx msg:  %v\n", ts)

			//var eth layers.Ethernet
			var ip4 layers.IPv4
			var ic4 layers.ICMPv4

			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &ic4)
			parser.IgnoreUnsupported = true
			decoded := []gopacket.LayerType{}
			if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
				if len(decoded) == 2 && len(ic4.Payload) > 8 {
					id := ReadUInt64(ic4.Payload, 0)

					this.m_mutex.RLock()
					np, ok := this.m_nativePinger.Get(id)
					this.m_mutex.RUnlock()

					if ok && ip4.SrcIP.Equal(np.Job.IPAddress) && ic4.TypeCode == 0 && ic4.Seq == np.packet.SequenceNumber {

						addSample := false
						np.m_mutex.Lock()
						if np.timestampRecv == 0 {
							np.timestampRecv = ts
							if np.timestampSend != 0 {
								addSample = true
							}
						}
						np.m_mutex.Unlock()
						if addSample {
							this.addSample(np, id, true)
						}
					}
				}

				// for _, layerType := range decoded {
				// 	switch layerType {
				// 	// case layers.LayerTypeIPv6:
				// 	// 	fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
				// 	case layers.LayerTypeIPv4:
				// 		fmt.Println("rx IP4: ", ip4.SrcIP, ip4.DstIP)
				// 	case layers.LayerTypeICMPv4:
				// 		fmt.Println("rx IC4: ", ic4.Seq, ic4.Payload)
				// 	}
				// }
			} else {
				fmt.Println("err ", err)
			}
		}
	}
}

func (this *ICMPNative) error_thread() {
	data := make([]byte, syscall.Getpagesize())
	for true {
		ndata, ts := recvpacket_v4(this.m_socket, data, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT, this.m_timestamp_type)
		if ndata == -1 {
			fds := []unix.PollFd{{Fd: int32(this.m_socket), Events: unix.POLLERR}}
			unix.Poll(fds, 2100)
			//fmt.Printf("tx poll: %v %v\n", fds[0].Events, fds[0].Revents)
			continue
		} else if ndata < 0 {
			panic(ndata)
		} else {
			// ihl := (data[0] & 0x0F) * 4
			// fmt.Printf("tx data: %v - % X\n", ndata, data[14:ndata])
			// fmt.Printf("tx msg:  %v\n", ts)

			var eth layers.Ethernet
			var ip4 layers.IPv4
			var ic4 layers.ICMPv4

			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ic4)
			parser.IgnoreUnsupported = true
			decoded := []gopacket.LayerType{}
			if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
				if len(decoded) == 3 {
					id := ReadUInt64(ic4.Payload, 0)

					this.m_mutex.RLock()
					np, ok := this.m_nativePinger.Get(id)
					this.m_mutex.RUnlock()

					// fmt.Println("rx YYY", ok, ip4.DstIP.Equal(np.Job.IPAddress), ic4.TypeCode == (8 << 8) , ic4.Seq == np.packet.SequenceNumber)
					if ok && ip4.DstIP.Equal(np.Job.IPAddress) && ic4.TypeCode == (8<<8) && ic4.Seq == np.packet.SequenceNumber {
						np.m_mutex.Lock()
						if np.timestampSend == 0 {
							np.timestampSend = ts
							if np.timestampRecv != 0 {
								this.addSample(np, id, true)
							}
						}
						np.m_mutex.Unlock()
					}
				}

				// for _, layerType := range decoded {
				// 	switch layerType {
				// 	// case layers.LayerTypeIPv6:
				// 	// 	fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
				// 	case layers.LayerTypeIPv4:
				// 		fmt.Println("tx IP4: ", ip4.SrcIP, ip4.DstIP)
				// 	case layers.LayerTypeICMPv4:
				// 		fmt.Println("tx IC4: ", ic4.Seq, ic4.Payload)
				// 	}
				// }
			} else {
				fmt.Println("err ", err)
			}
		}
	}
}

// func socket_set_ioctl(fd int, name string, so_timestamping_flags int) error {

// 	if len(name) >= unix.IFNAMSIZ {
// 		return fmt.Errorf("interface name too long")
// 	}

// 	ts := ifreq{
// 		ifr_data: hwtstamp_config{},
// 	}

// 	if so_timestamping_flags&unix.SOF_TIMESTAMPING_TX_HARDWARE > 0 {
// 		ts.ifr_data.tx_type = 1
// 	}
// 	if so_timestamping_flags&unix.SOF_TIMESTAMPING_RX_HARDWARE > 0 {
// 		ts.ifr_data.rx_filter = 1
// 	}

// 	copy(ts.ifr_name[:], name)

// 	fmt.Printf("flags: %v, tx_type: %v, rx_filters: %v\n", ts.ifr_data.flags, ts.ifr_data.tx_type, ts.ifr_data.rx_filter)

// 	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name); err != nil {
// 		panic(err)
// 	}
// 	if _, _, err := unix.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCSHWTSTAMP), uintptr(unsafe.Pointer(&ts))); err < 0 {
// 		panic(err)
// 		// return err
// 	}
// 	fmt.Printf("flags: %v, tx_type: %v, rx_filters: %v\n", ts.ifr_data.flags, ts.ifr_data.tx_type, ts.ifr_data.rx_filter)

// 	return nil
// }

func socket_set_flags(fd int, so_timestamping_flags int, so_timestamp int, so_timestampns int) error {

	if so_timestamp > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP); err != nil {
			panic(err)
		} else {
			fmt.Printf("SO_TIMESTAMP:    %v %v\n", val, 1)
		}
	}

	if so_timestampns > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS); err != nil {
			panic(err)
		} else {
			fmt.Printf("SO_TIMESTAMPNS:  %v %v\n", val, 1)
		}
	}

	if so_timestamping_flags > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPING, so_timestamping_flags); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPING); err != nil {
			panic(err)
		} else {
			fmt.Printf("SO_TIMESTAMPING: %v %v\n", val, so_timestamping_flags)
		}
	}

	if false {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.IPV6_V6ONLY); err != nil {
			panic(err)
		} else {
			fmt.Printf("IPV6_V6ONLY: %v %v\n", val, 0)
		}
	}

	return nil
}
