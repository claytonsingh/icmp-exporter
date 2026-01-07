package netprobe

import (
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	syscall "golang.org/x/sys/unix"
)

var (
	options = []layers.TCPOption{
		{
			OptionType:   255,
			OptionLength: 37,
			OptionData:   []byte("github.com/claytonsingh/icmp-exporter"),
		},
	}
)

type tcpPinger struct {
	timestampStart time.Time
	timestampSend  int64
	timestampRecv  int64
	packet         TcpPacket
	probe          *PingProbe
	mutex          sync.Mutex
}

type TCPNative struct {
	socket4        int
	socket6        int
	tcpPinger      *SafeOrderedMap[uint64, *tcpPinger]
	started        bool
	timeout        time.Duration
	timestampType  int
	timestampFlags int
	interface4     string
	interface6     string
	srcIP4         net.IP
	srcIP6         net.IP
	srcPortMin     uint16
	srcPortMax     uint16
	transmitBuffer gopacket.SerializeBuffer
	random         *rand.Rand
	sentCount      atomic.Int64
	recvCount      atomic.Int64
	errorCount     atomic.Int64
}

func NewTCPNative(hardware bool, iface4 string, iface6 string, timeout int, identifier uint16, minPort uint16, maxPort uint16) *TCPNative {
	var this TCPNative
	this.tcpPinger = NewSafeOrderedMap[uint64, *tcpPinger]()
	this.timeout = time.Duration(timeout) * time.Millisecond
	this.interface4 = iface4
	this.interface6 = iface6
	this.transmitBuffer = gopacket.NewSerializeBuffer()
	this.random = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))

	// Use a random source port range to avoid conflicts
	this.srcPortMin = minPort
	this.srcPortMax = maxPort

	if hardware {
		this.timestampFlags = syscall.SOF_TIMESTAMPING_RX_HARDWARE | syscall.SOF_TIMESTAMPING_TX_HARDWARE | syscall.SOF_TIMESTAMPING_RAW_HARDWARE
		this.timestampType = 2
	} else {
		this.timestampFlags = syscall.SOF_TIMESTAMPING_RX_SOFTWARE | syscall.SOF_TIMESTAMPING_TX_SOFTWARE | syscall.SOF_TIMESTAMPING_SOFTWARE
		this.timestampType = 0
	}

	return &this
}

func (this *TCPNative) Start() {
	if this.started {
		return
	}
	this.started = true

	if this.interface4 != "" {
		if socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP); err != nil {
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
			// Check for tcp
			bpf.LoadAbsolute{Off: 9, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 10},
			// Check ipv4 flags. Ignore if any are set
			bpf.LoadAbsolute{Off: 6, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1FFF, SkipTrue: 8},

			// Save ipv4 header length into X
			bpf.LoadMemShift{Off: 0},

			// check tcp flags for SYN & ACK
			bpf.LoadIndirect{Off: 13, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpBitsNotSet, Val: 0x10, SkipTrue: 5},
			bpf.JumpIf{Cond: bpf.JumpBitsNotSet, Val: 0x02, SkipTrue: 4},

			bpf.LoadIndirect{Off: 2, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpLessThan, Val: uint32(this.srcPortMin), SkipTrue: 2},
			bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: uint32(this.srcPortMax), SkipTrue: 1},

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
		if socket, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP); err != nil {
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
			// check tcp flags for SYN & ACK
			bpf.LoadAbsolute{Off: 13, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpBitsNotSet, Val: 0x10, SkipTrue: 5},
			bpf.JumpIf{Cond: bpf.JumpBitsNotSet, Val: 0x02, SkipTrue: 4},

			bpf.LoadAbsolute{Off: 2, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpLessThan, Val: uint32(this.srcPortMin), SkipTrue: 2},
			bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: uint32(this.srcPortMax), SkipTrue: 1},

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
		go this.receiveThread4()
		go this.errorThread4()
	}
	if this.socket6 > 0 {
		go this.receiveThread6()
		go this.errorThread6()
	}
	go this.timeoutThread()
}

func (this *TCPNative) timeoutThread() {
	for {
		if key, pinger, ok := this.tcpPinger.Front(); !ok {
			time.Sleep(this.timeout)
		} else {
			dt := pinger.timestampStart.Sub(time.Now()) + this.timeout

			if dt > 0 {
				time.Sleep(dt)
			}

			this.tcpPinger.Delete(key)

			pinger.mutex.Lock()

			// Things like failed arp cause tx failures on sockets, so mark those as failed pings
			if pinger.timestampSend == 0 || pinger.timestampSend == -1 {
				// Increment sent packets counter
				this.sentCount.Add(1)

				pinger.probe.AddSample(PingResult{
					Success:      false,
					RountripTime: 0,
					Timestamp:    pinger.timestampStart,
				})
			} else if pinger.timestampSend > 0 && pinger.timestampRecv != -1 && (pinger.timestampRecv == 0 || pinger.timestampSend <= pinger.timestampRecv) {
				// Increment sent packets counter
				this.sentCount.Add(1)

				// if both sent and recv are set then we count it as a success
				if pinger.timestampRecv > 0 {
					pinger.probe.AddSample(PingResult{
						Success:      true,
						RountripTime: pinger.timestampRecv - pinger.timestampSend,
						Timestamp:    pinger.timestampStart,
					})
					this.recvCount.Add(1)
				} else {
					pinger.probe.AddSample(PingResult{
						Success:      false,
						RountripTime: 0,
						Timestamp:    pinger.timestampStart,
					})
				}
			} else {
				// if there was an error dont count the packet
				this.errorCount.Add(1)
			}
			pinger.mutex.Unlock()
		}
	}
}

func (this *TCPNative) IncrementSequenceNumber() {
	// If the interface changes, we need to update the source IP
	if this.socket4 > 0 && this.interface4 != "" {
		this.srcIP4, _ = getInterfaceIP(this.interface4, true)
	}
	if this.socket6 > 0 && this.interface6 != "" {
		this.srcIP6, _ = getInterfaceIP(this.interface6, false)
	}
}

func (this *TCPNative) Transmit(probe *PingProbe) {

	// Find a random sequence number that is not in use
	var id uint64
	for {
		// Generate a random number between [srcPortMin, srcPortMax] in the upper 32 bits and the sequence number in the lower 32 bits
		id = this.random.Uint64N(uint64(this.srcPortMax-this.srcPortMin+1)<<32) + uint64(this.srcPortMin)<<32
		// Avoid the last 16 sequence numbers to avoid integer wrapping
		if id&0xFFFFFFFF > 0xFFFFFFF0 {
			continue
		}
		if _, ok := this.tcpPinger.Get(id); !ok {
			break
		}
	}
	sequenceNumber := uint32(id & 0xFFFFFFFF)
	srcPort := uint16(id >> 32)

	var pinger tcpPinger
	pinger.timestampStart = time.Now()
	pinger.probe = probe

	if IsIPv4(pinger.probe.IPAddress) {
		if this.socket4 > 0 && this.srcIP4 != nil {
			this.tcpPinger.Set(id, &pinger)
			pinger.packet = TcpPacket{
				SourcePort:      srcPort,
				DestinationPort: pinger.probe.TCPPort,
				SequenceNumber:  sequenceNumber,
				Acknowledgment:  0,
				DataOffset:      5, // 20 bytes header
				Flags:           TCP_FLAG_SYN,
				WindowSize:      65535,
				Checksum:        0,
				UrgentPointer:   0,
				Options:         []byte{},
				Payload:         []byte{},
			}

			err := TcpSerialize(this.transmitBuffer, this.srcIP4, pinger.probe.IPAddress, srcPort, pinger.probe.TCPPort, sequenceNumber, TCP_FLAG_SYN, options, []byte{})
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
		if this.socket6 > 0 && this.srcIP6 != nil {
			this.tcpPinger.Set(id, &pinger)
			pinger.packet = TcpPacket{
				SourcePort:      srcPort,
				DestinationPort: pinger.probe.TCPPort,
				SequenceNumber:  sequenceNumber,
				Acknowledgment:  0,
				DataOffset:      5, // 20 bytes header
				Flags:           TCP_FLAG_SYN,
				WindowSize:      65535,
				Checksum:        0,
				UrgentPointer:   0,
				Options:         []byte{},
				Payload:         []byte{},
			}

			err := TcpSerialize(this.transmitBuffer, this.srcIP6, pinger.probe.IPAddress, srcPort, pinger.probe.TCPPort, sequenceNumber, TCP_FLAG_SYN, options, []byte{})
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

func (this *TCPNative) receiveThread4() {
	var ip4 layers.IPv4
	var tcp4 layers.TCP
	parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp4)
	parser4.IgnoreUnsupported = true

	data := make([]byte, syscall.Getpagesize())
	for {
		ip, ndata, ts := recvpacket_v4(this.socket4, data, 0, this.timestampType)
		if ndata < 0 {
			panic(ndata)
		} else if ip != nil {
			decoded := []gopacket.LayerType{}
			if err := parser4.DecodeLayers(data[:ndata], &decoded); err == nil {
				for _, layer := range decoded {
					if layer == layers.LayerTypeTCP {

						// Ack is one higher then the sequence number of the SYN we sent
						id := uint64(tcp4.DstPort)<<32 + uint64(tcp4.Ack-1)
						np, ok := this.tcpPinger.Get(id)

						if ok && tcp4.ACK && tcp4.SYN && np.probe.IPAddress.Equal(ip4.SrcIP) && tcp4.SrcPort == layers.TCPPort(np.probe.TCPPort) && tcp4.DstPort == layers.TCPPort(np.packet.SourcePort) {
							np.mutex.Lock()
							if np.timestampRecv == 0 {
								np.timestampRecv = ts
							}
							np.mutex.Unlock()
						}
					}
				}
			} else {
				fmt.Println("tcp rx err ", err)
			}
		}
	}
}

func (this *TCPNative) receiveThread6() {
	var tcp6 layers.TCP
	parser6 := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &tcp6)
	parser6.IgnoreUnsupported = true

	data := make([]byte, syscall.Getpagesize())
	for {
		ip, ndata, ts := recvpacket_v4(this.socket6, data, 0, this.timestampType)
		if ndata < 0 {
			panic(ndata)
		} else if ip != nil {
			decoded := []gopacket.LayerType{}
			if err := parser6.DecodeLayers(data[:ndata], &decoded); err == nil {
				for _, layer := range decoded {
					if layer == layers.LayerTypeTCP {
						id := uint64(tcp6.DstPort)<<32 + uint64(tcp6.Ack-1)
						np, ok := this.tcpPinger.Get(id)

						if ok && tcp6.ACK && tcp6.SYN && np.probe.IPAddress.Equal(ip) && tcp6.SrcPort == layers.TCPPort(np.probe.TCPPort) && tcp6.DstPort == layers.TCPPort(np.packet.SourcePort) {
							np.mutex.Lock()
							if np.timestampRecv == 0 {
								np.timestampRecv = ts
							}
							np.mutex.Unlock()
						}
					}
				}
			} else {
				fmt.Println("tcp rx err ", err)
			}
		}
	}
}

func (this *TCPNative) errorThread4() {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
	parser.IgnoreUnsupported = true

	data := make([]byte, syscall.Getpagesize())
	for {
		_, ndata, ts := recvpacket_v4(this.socket4, data, syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT, this.timestampType)
		if ndata == -1 {
			fds := []syscall.PollFd{{Fd: int32(this.socket4), Events: syscall.POLLERR}}
			syscall.Poll(fds, 2100)
			continue
		} else if ndata < 0 {
			panic(ndata)
		} else {
			decoded := []gopacket.LayerType{}
			if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
				for _, layer := range decoded {
					if layer == layers.LayerTypeTCP {
						// Read the sequence number from the packet
						id := uint64(tcp.SrcPort)<<32 + uint64(tcp.Seq)
						np, ok := this.tcpPinger.Get(id)

						if ok && tcp.DstPort == layers.TCPPort(np.probe.TCPPort) && tcp.SrcPort == layers.TCPPort(np.packet.SourcePort) && ip4.DstIP.Equal(np.probe.IPAddress) {
							np.mutex.Lock()
							if np.timestampSend == 0 {
								np.timestampSend = ts
							}
							np.mutex.Unlock()
						}
					}
				}
			} else {
				fmt.Println("tcp er err ", err)
			}
		}
	}
}

func (this *TCPNative) errorThread6() {
	var eth layers.Ethernet
	var ip6 layers.IPv6
	var tcp layers.TCP

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &tcp)
	parser.IgnoreUnsupported = true

	data := make([]byte, syscall.Getpagesize())
	for {
		_, ndata, ts := recvpacket_v4(this.socket6, data, syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT, this.timestampType)
		if ndata == -1 {
			fds := []syscall.PollFd{{Fd: int32(this.socket6), Events: syscall.POLLERR}}
			syscall.Poll(fds, 2100)
			continue
		} else if ndata < 0 {
			panic(ndata)
		} else {
			decoded := []gopacket.LayerType{}
			if err := parser.DecodeLayers(data[:ndata], &decoded); err == nil {
				for _, layer := range decoded {
					if layer == layers.LayerTypeTCP {
						// Read the sequence number from the packet
						id := uint64(tcp.SrcPort)<<32 + uint64(tcp.Seq)
						np, ok := this.tcpPinger.Get(id)

						if ok && tcp.DstPort == layers.TCPPort(np.probe.TCPPort) && tcp.SrcPort == layers.TCPPort(np.packet.SourcePort) && ip6.DstIP.Equal(np.probe.IPAddress) {
							np.mutex.Lock()
							if np.timestampSend == 0 {
								np.timestampSend = ts
							}
							np.mutex.Unlock()
						}
					}
				}
			} else {
				fmt.Println("tcp er err ", err)
			}
		}
	}
}

// GetSentCount returns the total number of TCP packets sent
func (this *TCPNative) GetSentCount() int64 {
	return this.sentCount.Load()
}

// GetReceivedCount returns the total number of TCP packets received
func (this *TCPNative) GetReceivedCount() int64 {
	return this.recvCount.Load()
}

// GetErrorCount returns the total number of TCP socket errors
func (this *TCPNative) GetErrorCount() int64 {
	return this.errorCount.Load()
}
