package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/net/bpf"
	syscall "golang.org/x/sys/unix"
)

var (
	txPackets = promauto.NewCounter(prometheus.CounterOpts{
		Name: "icmp_packets_sent_total",
		Help: "The total number of transmitted packets",
	})
	rxPackets = promauto.NewCounter(prometheus.CounterOpts{
		Name: "icmp_packets_recv_total",
		Help: "The total number of received packets",
	})
	erPackets = promauto.NewCounter(prometheus.CounterOpts{
		Name: "icmp_packets_error_total",
		Help: "The total number of error packets",
	})
	activeProbes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "icmp_active_probes",
		Help: "The number of active probes",
	})
)

const (
	payload = "\000\000\000\000\000\000\000\000....github.com/claytonsingh/icmp-exporter......."
	//                                 ........................................................
)

type nativePinger struct {
	timestampStart time.Time
	timestampSend  int64
	timestampRecv  int64
	packet         IcmpPacket
	probe          *PingProbe
	mutex          sync.Mutex
}

type ICMPNative struct {
	socket4        int
	socket6        int
	nativePinger   *SafeOrderedMap[uint64, *nativePinger]
	started        bool
	timeout        time.Duration
	identifier     uint16
	timestampType  int
	timestampFlags int
	interface4     string
	interface6     string
	srcIP4         net.IP
	srcIP6         net.IP
	transmitBuffer gopacket.SerializeBuffer
	SequenceNumber uint16
	id             uint64
}

func NewICMPNative(hardware bool, iface4 string, iface6 string, timeout int, identifier uint16) *ICMPNative {
	var this ICMPNative
	this.nativePinger = NewSafeOrderedMap[uint64, *nativePinger]()
	this.timeout = time.Duration(timeout) * time.Millisecond
	this.interface4 = iface4
	this.interface6 = iface6
	this.transmitBuffer = gopacket.NewSerializeBuffer()

	this.identifier = identifier
	if this.identifier == 0 { // Default identifier is pid
		this.identifier = (uint16)(os.Getpid())
	}
	if this.identifier == 1 { // If this is launched in a docker container then we are pid 1 so pick a random identifier
		this.identifier = (uint16)(rand.Intn(65535))
	}

	if hardware {
		this.timestampFlags = syscall.SOF_TIMESTAMPING_RX_HARDWARE | syscall.SOF_TIMESTAMPING_TX_HARDWARE | syscall.SOF_TIMESTAMPING_RAW_HARDWARE
		this.timestampType = 2
	} else {
		this.timestampFlags = syscall.SOF_TIMESTAMPING_RX_SOFTWARE | syscall.SOF_TIMESTAMPING_TX_SOFTWARE | syscall.SOF_TIMESTAMPING_SOFTWARE
		this.timestampType = 0
	}

	return &this
}

func (this *ICMPNative) Start() {
	if this.started {
		return
	}
	this.started = true

	/// ICMP
	if this.interface4 != "" {
		if socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP); err != nil {
			panic(err)
		} else {
			this.socket4 = socket
		}

		if err := socket_set_ioctl_native(this.socket4, this.interface4, this.timestampFlags); err < 0 {
			panic(err)
		}
		if err := socket_set_flags(this.socket4, 4, this.timestampFlags, 0, 0); err != nil {
			panic(err)
		}

		if err := (BpfFilter{
			// Check for ipv4
			bpf.LoadAbsolute{Off: 9, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 1, SkipTrue: 8},
			// Check ipv4 flags. Ignore if any are set
			bpf.LoadAbsolute{Off: 6, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1FFF, SkipTrue: 6},
			// Save ipv4 header length into X
			bpf.LoadMemShift{Off: 0},
			// Load icmp "Type" and "Code" fields. Ignore if the type/code is not icmp echo response
			bpf.LoadIndirect{Off: 0, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0, SkipTrue: 3, SkipFalse: 0},
			// Load icmp "identifier" field. Ignore if the identifier is not ours
			bpf.LoadIndirect{Off: 4, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(this.identifier), SkipTrue: 1},
			// Verdict is "send up to 4k of the packet to userspace."
			bpf.RetConstant{Val: 4096},
			// Verdict is "ignore packet."
			bpf.RetConstant{Val: 0},
		}.ApplyTo(this.socket4)); err != nil {
			panic(err)
		}

		this.srcIP4, _ = getInterfaceIP(this.interface4, true)
	}

	if this.interface6 != "" {
		if socket, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6); err != nil {
			panic(err)
		} else {
			this.socket6 = socket
		}

		if err := socket_set_ioctl_native(this.socket6, this.interface6, this.timestampFlags); err < 0 {
			panic(err)
		}
		if err := socket_set_flags(this.socket6, 6, this.timestampFlags, 0, 0); err != nil {
			panic(err)
		}

		// ipv6 is shit, so we only get the payload and not a whole packet. There is no way to generate a filter so hand roll it.
		if err := (BpfFilter{
			// Load "Type" and "Code" fields. Exit 0 if the type/code is not icmp echo response
			bpf.LoadAbsolute{Off: 0, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x8100, SkipTrue: 3},
			// Load "identifier" field. Exit 0 if the identifier is not ours
			bpf.LoadAbsolute{Off: 4, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(this.identifier), SkipTrue: 1},
			// Verdict is "send up to 4k of the packet to userspace."
			bpf.RetConstant{Val: 4096},
			// Verdict is "ignore packet."
			bpf.RetConstant{Val: 0},
		}.ApplyTo(this.socket6)); err != nil {
			panic(err)
		}

		this.srcIP6, _ = getInterfaceIP(this.interface6, false)
	}

	if this.socket4 > 0 {
		go this.receiveIcmp4()
		go this.errorIcmp4()
	}
	if this.socket6 > 0 {
		go this.receiveIcmp6()
		go this.errorIcmp6()
	}

	go this.timeoutThread()
}

func (this *ICMPNative) timeoutThread() {
	for {
		if key, pinger, ok := this.nativePinger.Front(); !ok {
			time.Sleep(this.timeout)
		} else {
			dt := pinger.timestampStart.Sub(time.Now()) + this.timeout

			if dt > 0 {
				time.Sleep(dt)
			}

			this.nativePinger.Delete(key)

			pinger.mutex.Lock()

			// Things like failed arp cause tx failures on sockets, so mark those as failed pings
			if pinger.timestampSend == 0 || pinger.timestampSend == -1 {
				// Increment sent packets counter
				txPackets.Inc()

				pinger.probe.AddSample(PingResult{
					Success:      false,
					RountripTime: 0,
					Timestamp:    pinger.timestampStart,
				})
			} else if pinger.timestampSend > 0 && pinger.timestampRecv != -1 && (pinger.timestampRecv == 0 || pinger.timestampSend <= pinger.timestampRecv) {
				// Increment sent packets counter
				txPackets.Inc()

				// if both sent and recv are set then we count it as a success
				if pinger.timestampRecv > 0 {
					pinger.probe.AddSample(PingResult{
						Success:      true,
						RountripTime: pinger.timestampRecv - pinger.timestampSend,
						Timestamp:    pinger.timestampStart,
					})
					rxPackets.Inc()
				} else {
					pinger.probe.AddSample(PingResult{
						Success:      false,
						RountripTime: 0,
						Timestamp:    pinger.timestampStart,
					})
				}
			} else {
				// if there was an error dont count the packet
				// fmt.Println(pinger.timestampSend, pinger.timestampRecv, pinger.probe.IPAddress)
				erPackets.Inc()
			}
			pinger.mutex.Unlock()
		}
	}
}

func (this *ICMPNative) IncrementSequenceNumber() {
	this.SequenceNumber += 1

	// If the interface changes, we need to update the source IP
	if this.socket4 > 0 && this.interface4 != "" {
		this.srcIP4, _ = getInterfaceIP(this.interface4, true)
	}
	if this.socket6 > 0 && this.interface6 != "" {
		this.srcIP6, _ = getInterfaceIP(this.interface6, false)
	}
}

func (this *ICMPNative) Transmit(probe *PingProbe) {
	this.id = this.id + 1

	var pinger nativePinger
	pinger.timestampStart = time.Now()
	pinger.probe = probe

	if IsIPv4(pinger.probe.IPAddress) {
		if this.socket4 > 0 {
			this.nativePinger.Set(this.id, &pinger)
			pinger.packet = IcmpPacket{
				Type:           8,
				Code:           0,
				Identifier:     this.identifier,
				SequenceNumber: this.SequenceNumber,
				Payload:        make([]byte, len(payload)),
			}
			copy(pinger.packet.Payload, payload)
			WriteUint64(pinger.packet.Payload, 0, this.id)

			err := IcmpSerialize(this.transmitBuffer, this.srcIP4, pinger.probe.IPAddress, this.identifier, this.SequenceNumber, pinger.packet.Payload)
			if err != nil {
				panic(err)
			}
			address := syscall.SockaddrInet4{Addr: Ipv4ToBytes(pinger.probe.IPAddress)}
			pinger.mutex.Lock()
			if err := syscall.Sendto(this.socket4, this.transmitBuffer.Bytes(), 0, &address); err != nil {
				switch err {
				case syscall.ENETUNREACH: // network is unreachable
				case syscall.EHOSTUNREACH: // host is unreachable
				case syscall.EACCES: // things like arp failed at L2 ( permission denied )
					pinger.timestampSend = -1
				default:
					panic(err)
				}
			}
			pinger.mutex.Unlock()
		}
	} else {
		if this.socket6 > 0 {
			this.nativePinger.Set(this.id, &pinger)
			pinger.packet = IcmpPacket{
				Type:           128,
				Code:           0,
				Identifier:     this.identifier,
				SequenceNumber: this.SequenceNumber,
				Payload:        make([]byte, len(payload)),
			}
			copy(pinger.packet.Payload, payload)
			WriteUint64(pinger.packet.Payload, 0, this.id)

			err := IcmpSerialize(this.transmitBuffer, this.srcIP6, pinger.probe.IPAddress, this.identifier, this.SequenceNumber, pinger.packet.Payload)
			if err != nil {
				panic(err)
			}
			address := syscall.SockaddrInet6{Addr: Ipv6ToBytes(pinger.probe.IPAddress)}
			pinger.mutex.Lock()
			if err := syscall.Sendto(this.socket6, this.transmitBuffer.Bytes(), 0, &address); err != nil {
				switch err {
				case syscall.ENETUNREACH: // network is unreachable
				case syscall.EHOSTUNREACH: // host is unreachable
				case syscall.EACCES: // things like arp failed at L2 ( permission denied )
					pinger.timestampSend = -1
				default:
					panic(err)
				}
			}
			pinger.mutex.Unlock()
		}
	}
}

func readSocket(sock int, data []byte, timestampType int) (ip net.IP, ndata int, ts int64) {
	for {
		ip, ndata, ts = recvpacket_v4(sock, data, 0, timestampType)
		if ndata < 0 {
			panic(ndata)
		} else if ip != nil {
			return ip, ndata, ts
		}
	}
}

func (this *ICMPNative) receiveIcmp4() {
	var ip4 layers.IPv4
	var ic4 layers.ICMPv4
	parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &ic4)
	parser4.IgnoreUnsupported = true

	data := make([]byte, syscall.Getpagesize())
	for {
		ip, ndata, ts := readSocket(this.socket4, data, this.timestampType)
		if IsIPv4(ip) {
			decoded := []gopacket.LayerType{}
			if err := parser4.DecodeLayers(data[:ndata], &decoded); err == nil {
				for _, layer := range decoded {
					if layer == layers.LayerTypeICMPv4 {
						if len(ic4.Payload) >= 8 {
							id := ReadUInt64(ic4.Payload, 0)

							np, ok := this.nativePinger.Get(id)

							if ok && np.probe.IPAddress.Equal(ip4.SrcIP) && ic4.TypeCode == 0 && ic4.Seq == np.packet.SequenceNumber {
								np.mutex.Lock()
								if np.timestampRecv == 0 {
									np.timestampRecv = ts
								}
								np.mutex.Unlock()
							}
						}
					}
				}
			} else {
				fmt.Println("rx err ", err)
			}
		}
	}
}

func (this *ICMPNative) receiveIcmp6() {
	var ic6 layers.ICMPv6
	parser6 := gopacket.NewDecodingLayerParser(layers.LayerTypeICMPv6, &ic6)
	parser6.IgnoreUnsupported = true

	data := make([]byte, syscall.Getpagesize())
	for {
		ip, ndata, ts := readSocket(this.socket6, data, this.timestampType)
		if IsIPv6(ip) {
			decoded := []gopacket.LayerType{}
			if err := parser6.DecodeLayers(data[:ndata], &decoded); err == nil {
				for _, layer := range decoded {
					if layer == layers.LayerTypeICMPv6 {
						if len(ic6.Payload) >= 12 {
							id := ReadUInt64(ic6.Payload, 4)
							Seq := ReadUInt16(ic6.Payload, 2)

							np, ok := this.nativePinger.Get(id)

							if ok && np.probe.IPAddress.Equal(ip) && ic6.TypeCode&0xFF00 == 0x8100 && Seq == np.packet.SequenceNumber {
								np.mutex.Lock()
								if np.timestampRecv == 0 {
									np.timestampRecv = ts
								}
								np.mutex.Unlock()
							}
						}
					}
				}
			} else {
				fmt.Println("rx err ", err)
			}
		}
	}
}

func readSocketErr(sock int, data []byte, timestampType int) (ip net.IP, ndata int, ts int64) {
	fds := []syscall.PollFd{{Fd: int32(sock), Events: syscall.POLLERR}}
	for {
		_, ndata, ts = recvpacket_v4(sock, data, syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT, timestampType)
		if ndata == -1 {
			syscall.Poll(fds, 2100)
			continue
		} else if ndata < 0 {
			panic(ndata)
		} else if ndata == 0 {
			continue
		}
		return ip, ndata, ts
	}
}

func (this *ICMPNative) errorIcmp4() {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ic4 layers.ICMPv4

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ic4)
	parser.IgnoreUnsupported = true

	data := make([]byte, syscall.Getpagesize())
	for {
		_, ndata, ts := readSocketErr(this.socket4, data, this.timestampType)
		decoded := []gopacket.LayerType{}
		if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
			for _, layer := range decoded {
				if layer == layers.LayerTypeICMPv4 {
					id := ReadUInt64(ic4.Payload, 0)

					np, ok := this.nativePinger.Get(id)

					if ok && ip4.DstIP.Equal(np.probe.IPAddress) && ic4.TypeCode == (8<<8) && ic4.Seq == np.packet.SequenceNumber {
						np.mutex.Lock()
						if np.timestampSend == 0 {
							np.timestampSend = ts
						}
						np.mutex.Unlock()
					}
					break
				}
			}
		} else {
			fmt.Println("er err ", err)
		}
	}
}

func (this *ICMPNative) errorIcmp6() {
	var eth layers.Ethernet
	var ip6 layers.IPv6
	var ic6 layers.ICMPv6

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &ic6)
	parser.IgnoreUnsupported = true

	data := make([]byte, syscall.Getpagesize())
	for {
		_, ndata, ts := readSocketErr(this.socket6, data, this.timestampType)
		decoded := []gopacket.LayerType{}
		if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
			if slices.Contains(decoded, layers.LayerTypeICMPv6) {
				id := ReadUInt64(ip6.Payload, 8)
				Seq := ReadUInt16(ip6.Payload, 6)

				np, ok := this.nativePinger.Get(id)

				if ok && ip6.DstIP.Equal(np.probe.IPAddress) && ic6.TypeCode&0xFF00 == 0x8000 && Seq == np.packet.SequenceNumber {
					np.mutex.Lock()
					if np.timestampSend == 0 {
						np.timestampSend = ts
					}
					np.mutex.Unlock()
				}
			}
		} else {
			fmt.Println("er err ", err)
		}
	}
}

//lint:ignore ST1003 match c api
func socket_set_flags(fd int, ipversion int, so_timestamping_flags int, so_timestamp int, so_timestampns int) error {

	if so_timestamp > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP); err != nil {
			panic(err)
		} else {
			log.Printf("SO_TIMESTAMP:    %v %v\n", val, 1)
		}
	}

	if so_timestampns > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS); err != nil {
			panic(err)
		} else {
			log.Printf("SO_TIMESTAMPNS:  %v %v\n", val, 1)
		}
	}

	if so_timestamping_flags > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPING, so_timestamping_flags); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPING); err != nil {
			panic(err)
		} else {
			log.Printf("SO_TIMESTAMPING: %v %v\n", val, so_timestamping_flags)
		}
	}

	if false {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.IPV6_V6ONLY); err != nil {
			panic(err)
		} else {
			log.Printf("IPV6_V6ONLY: %v %v\n", val, 0)
		}
	}

	switch ipversion {
	case 4:
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			return err
		}
	case 6:
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_HDRINCL, 1); err != nil {
			return err
		}
	}

	return nil
}
