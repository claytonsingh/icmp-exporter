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
	m_socket_4        int
	m_socket_6        int
	m_nativePinger    *orderedmap.OrderedMap[uint64, *nativePinger]
	m_jobs            []*PingJob
	m_job_mutex       sync.Mutex
	m_mutex           sync.RWMutex
	m_started         bool
	m_timeout         time.Duration
	m_pingrate        float32
	m_identifier      uint16
	m_timestamp_type  int
	m_timestamp_flags int
	m_interface       string
	m_next_packet     time.Time
}

func NewICMPNative(hardware bool, iface string) *ICMPNative {
	var this ICMPNative
	this.m_identifier = (uint16)(os.Getpid())
	this.m_nativePinger = orderedmap.NewOrderedMap[uint64, *nativePinger]()
	this.m_timeout = time.Duration(3) * time.Second
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
		this.m_socket_4 = socket
	}

	if err := socket_set_ioctl_native(this.m_socket_4, this.m_interface, this.m_timestamp_flags); err < 0 {
		panic(err)
	}
	socket_set_flags(this.m_socket_4, this.m_timestamp_flags, 0, 0)

	if socket, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6); err != nil {
		panic(err)
	} else {
		this.m_socket_6 = socket
	}

	if err := socket_set_ioctl_native(this.m_socket_6, this.m_interface, this.m_timestamp_flags); err < 0 {
		panic(err)
	}
	socket_set_flags(this.m_socket_6, this.m_timestamp_flags, 0, 0)

	go this.timeout_thread()
	go this.transmit_thread()
	go this.receive_thread(this.m_socket_4)
	go this.receive_thread(this.m_socket_6)
	go this.error_thread(this.m_socket_4)
	go this.error_thread(this.m_socket_6)
}

func (this *ICMPNative) SetJobs(jobs []*PingJob) {
	this.m_job_mutex.Lock()
	this.m_jobs = jobs
	this.m_job_mutex.Unlock()
}

func (this *ICMPNative) timeout_thread() {
	for {
		this.m_mutex.RLock()
		front := this.m_nativePinger.Front()
		this.m_mutex.RUnlock()
		// fmt.Println(this.m_nativePinger)
		if front == nil {
			time.Sleep(this.m_timeout)
		} else {
			pinger := front.Value

			dt := pinger.timestampStart.Sub(time.Now()) + this.m_timeout
			// fmt.Println("DT:", dt, &pinger.Job, front.Key, pinger.Job.IPAddress, pinger.Job.Sent_count)
			if dt > 0 {
				time.Sleep(dt)
			}

			this.m_mutex.Lock()
			this.m_nativePinger.Delete(front.Key)
			this.m_mutex.Unlock()

			pinger.m_mutex.Lock()
			// if there was an error dont count the packet
			if pinger.timestampSend != -1 && pinger.timestampRecv != -1 && pinger.timestampSend <= pinger.timestampRecv {

				// if both sent and recv are set then we count it as a success
				if pinger.timestampSend > 0 && pinger.timestampRecv > 0 {
					pinger.Job.AddSample(PingResult{
						Success:      true,
						RountripTime: pinger.timestampRecv - pinger.timestampSend,
						Timestamp:    pinger.timestampStart,
					})
				} else {
					pinger.Job.AddSample(PingResult{
						Success:      false,
						RountripTime: 0,
						Timestamp:    pinger.timestampStart,
					})
				}
			}
			pinger.m_mutex.Unlock()
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
			continue
		}

		interpacket_duration := time.Duration(this.m_pingrate*1000) * time.Millisecond / time.Duration(len(jobs))

		for idx := range jobs {
			id = id + 1

			this.m_next_packet = this.m_next_packet.Add(interpacket_duration)

			now := time.Now()
			dt := this.m_next_packet.Sub(now)
			// fmt.Println("send", dt, interpacket_duration)
			if dt > 0 {
				time.Sleep(dt)
			} else if dt < time.Second {
				this.m_next_packet = now
			} else if dt < time.Millisecond*-10 {
				this.m_next_packet = now.Add(time.Millisecond * -10)
			}

			var x nativePinger
			x.timestampStart = time.Now()
			x.Job = jobs[idx]

			this.m_mutex.Lock()
			this.m_nativePinger.Set(id, &x)
			this.m_mutex.Unlock()

			if IsIPv4(x.Job.IPAddress) {
				x.packet = IcmpPacket{
					Type:           8,
					Code:           0,
					Identifier:     this.m_identifier,
					SequenceNumber: SequenceNumber,
					Payload:        []byte("\000\000\000\000\000\000\000\000....Hello World................................."),
					//                                              ........................................................
				}
				WriteUint64(x.packet.Payload, 0, id)

				n := x.packet.Serialize4(buf)
				address := syscall.SockaddrInet4{Addr: Ipv4ToBytes(x.Job.IPAddress)}
				if err := syscall.Sendto(this.m_socket_4, buf[:n], 0, &address); err != nil {
					panic(err)
				}
			} else {
				x.packet = IcmpPacket{
					Type:           128,
					Code:           0,
					Identifier:     this.m_identifier,
					SequenceNumber: SequenceNumber,
					Payload:        []byte("\000\000\000\000\000\000\000\000....Hello World................................."),
					//                                              ........................................................
				}
				WriteUint64(x.packet.Payload, 0, id)

				n := x.packet.Serialize6(buf)
				address := syscall.SockaddrInet6{Addr: Ipv6ToBytes(x.Job.IPAddress)}
				if err := syscall.Sendto(this.m_socket_6, buf[:n], 0, &address); err != nil {
					panic(err)
				}
			}
		}
		SequenceNumber += 1
	}
}

func (this *ICMPNative) receive_thread(sock int) {
	data := make([]byte, syscall.Getpagesize())
	for true {
		ip, ndata, ts := recvpacket_v4(sock, data, 0, this.m_timestamp_type)
		if ndata < 0 {
			panic(ndata)
		} else if ip != nil {
			//fmt.Printf("rx msg:  %v %v\n", ip.String(), ts)
			//fmt.Printf("rx data: %v - % X\n", ndata, data[:ndata])

			if IsIPv4(ip) {
				//var eth layers.Ethernet
				var ip4 layers.IPv4
				var ic4 layers.ICMPv4

				parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &ic4)
				parser.IgnoreUnsupported = true
				decoded := []gopacket.LayerType{}
				if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
					for _, layer := range decoded {
						if layer == layers.LayerTypeICMPv4 {
							if len(ic4.Payload) >= 8 {
								id := ReadUInt64(ic4.Payload, 0)

								this.m_mutex.RLock()
								np, ok := this.m_nativePinger.Get(id)
								this.m_mutex.RUnlock()

								if ok && np.Job.IPAddress.Equal(ip4.SrcIP) && ic4.TypeCode == 0 && ic4.Seq == np.packet.SequenceNumber {
									np.m_mutex.Lock()
									if np.timestampRecv == 0 {
										np.timestampRecv = ts
									}
									np.m_mutex.Unlock()
								}
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
					fmt.Println("rx err ", err)
				}
			} else if IsIPv6(ip) {
				var ic6 layers.ICMPv6

				parser := gopacket.NewDecodingLayerParser(layers.LayerTypeICMPv6, &ic6)
				parser.IgnoreUnsupported = true
				decoded := []gopacket.LayerType{}
				if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
					for _, layer := range decoded {
						if layer == layers.LayerTypeICMPv6 {
							if len(ic6.Payload) >= 12 {
								id := ReadUInt64(ic6.Payload, 4)
								Seq := ReadUInt16(ic6.Payload, 2)

								this.m_mutex.RLock()
								np, ok := this.m_nativePinger.Get(id)
								this.m_mutex.RUnlock()

								//fmt.Println("rx YYY", ok, np, ts)
								//fmt.Printf("tx2 data: %v - % X\n", ndata, data[:ndata])
								//fmt.Println("rx YYY", ok, ip4.DstIP.Equal(np.Job.IPAddress), ic4.TypeCode == (8<<8), ts)
								//fmt.Println("rx YYY", ok, ip6.DstIP, ic6.TypeCode == (128<<8), Seq == np.packet.SequenceNumber, ts)
								//fmt.Printf("tx3 data: % X\n", ip6.Payload)

								if ok && np.Job.IPAddress.Equal(ip) && ic6.TypeCode&0xFF00 == 0x8100 && Seq == np.packet.SequenceNumber {
									np.m_mutex.Lock()
									if np.timestampRecv == 0 {
										np.timestampRecv = ts
									}
									np.m_mutex.Unlock()
								}
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
					fmt.Println("rx err ", err)
				}
			}
		}
	}
}

func (this *ICMPNative) error_thread(sock int) {
	data := make([]byte, syscall.Getpagesize())
	for true {
		_, ndata, ts := recvpacket_v4(sock, data, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT, this.m_timestamp_type)
		if ndata == -1 {
			fds := []unix.PollFd{{Fd: int32(sock), Events: unix.POLLERR}}
			unix.Poll(fds, 2100)
			//fmt.Printf("tx poll: %v %v\n", fds[0].Events, fds[0].Revents)
			continue
		} else if ndata < 0 {
			panic(ndata)
		} else {
			// ihl := (data[0] & 0x0F) * 4
			// fmt.Printf("tx data: %v - % X\n", ndata, data[:ndata])
			// fmt.Printf("tx msg:  %v\n", ts)

			var eth layers.Ethernet
			var ip4 layers.IPv4
			var ic4 layers.ICMPv4
			var ip6 layers.IPv6
			var ic6 layers.ICMPv6

			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ic4, &ip6, &ic6)
			parser.IgnoreUnsupported = true
			decoded := []gopacket.LayerType{}
			if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
				for _, layer := range decoded {
					if layer == layers.LayerTypeICMPv4 {
						id := ReadUInt64(ic4.Payload, 0)

						this.m_mutex.RLock()
						np, ok := this.m_nativePinger.Get(id)
						this.m_mutex.RUnlock()

						// fmt.Println("rx YYY", ok, ip4.DstIP.Equal(np.Job.IPAddress), ic4.TypeCode == (8<<8), ic4.Seq == np.packet.SequenceNumber)
						if ok && ip4.DstIP.Equal(np.Job.IPAddress) && ic4.TypeCode == (8<<8) && ic4.Seq == np.packet.SequenceNumber {
							np.m_mutex.Lock()
							if np.timestampSend == 0 {
								np.timestampSend = ts
							}
							np.m_mutex.Unlock()
						}
						break
					} else if layer == layers.LayerTypeICMPv6 {
						id := ReadUInt64(ip6.Payload, 8)
						Seq := ReadUInt16(ip6.Payload, 6)

						this.m_mutex.RLock()
						np, ok := this.m_nativePinger.Get(id)
						this.m_mutex.RUnlock()

						//fmt.Println("rx YYY", ok, np, ts)
						//fmt.Printf("tx2 data: %v - % X\n", ndata, data[:ndata])
						//fmt.Println("rx YYY", ok, ip4.DstIP.Equal(np.Job.IPAddress), ic4.TypeCode == (8<<8), ts)
						//fmt.Println("rx YYY", ok, ip6.DstIP, ic6.TypeCode == (128<<8), Seq == np.packet.SequenceNumber, ts)
						//fmt.Printf("tx3 data: % X\n", ip6.Payload)

						if ok && ip6.DstIP.Equal(np.Job.IPAddress) && ic6.TypeCode&0xFF00 == 0x8000 && Seq == np.packet.SequenceNumber {
							np.m_mutex.Lock()
							if np.timestampSend == 0 {
								np.timestampSend = ts
							}
							np.m_mutex.Unlock()
						}
						break
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
				fmt.Println("er err ", err)
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
