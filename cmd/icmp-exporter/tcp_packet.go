package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TcpPacket struct {
	SourcePort      uint16
	DestinationPort uint16
	SequenceNumber  uint32
	Acknowledgment  uint32
	DataOffset      uint8
	Flags           uint8
	WindowSize      uint16
	Checksum        uint16
	UrgentPointer   uint16
	Options         []byte
	Payload         []byte
}

const (
	TCP_FLAG_FIN = 0x01
	TCP_FLAG_SYN = 0x02
	TCP_FLAG_RST = 0x04
	TCP_FLAG_PSH = 0x08
	TCP_FLAG_ACK = 0x10
	TCP_FLAG_URG = 0x20
)

func TcpSerialize(buf gopacket.SerializeBuffer, srcIP, dstIP net.IP, srcPort, dstPort uint16, sequenceNumber uint32, flags uint8, options []byte, payload []byte) error {
	if IsIPv4(dstIP) {
		ip := layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    srcIP.To4(),
			DstIP:    dstIP.To4(),
			Flags:    layers.IPv4DontFragment,
			Protocol: layers.IPProtocolTCP,
		}
		tcp := layers.TCP{
			SrcPort:    layers.TCPPort(srcPort),
			DstPort:    layers.TCPPort(dstPort),
			Seq:        sequenceNumber,
			Ack:        0,
			DataOffset: uint8(5 + len(options)/4), // 5 is the base header size in 32-bit words
			FIN:        (flags & TCP_FLAG_FIN) != 0,
			SYN:        (flags & TCP_FLAG_SYN) != 0,
			RST:        (flags & TCP_FLAG_RST) != 0,
			PSH:        (flags & TCP_FLAG_PSH) != 0,
			ACK:        (flags & TCP_FLAG_ACK) != 0,
			URG:        (flags & TCP_FLAG_URG) != 0,
			Window:     uint16(65535),
			Urgent:     0,
		}
		tcp.SetNetworkLayerForChecksum(&ip)

		layers := []gopacket.SerializableLayer{&ip, &tcp}
		if len(payload) > 0 {
			layers = append(layers, gopacket.Payload(payload))
		}

		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layers...); err != nil {
			return err
		}
	} else {
		ip := layers.IPv6{
			Version:    6,
			HopLimit:   64,
			SrcIP:      srcIP.To16(),
			DstIP:      dstIP.To16(),
			NextHeader: layers.IPProtocolTCP,
		}
		tcp := layers.TCP{
			SrcPort:    layers.TCPPort(srcPort),
			DstPort:    layers.TCPPort(dstPort),
			Seq:        sequenceNumber,
			Ack:        0,
			DataOffset: uint8(5 + len(options)/4),
			FIN:        (flags & TCP_FLAG_FIN) != 0,
			SYN:        (flags & TCP_FLAG_SYN) != 0,
			RST:        (flags & TCP_FLAG_RST) != 0,
			PSH:        (flags & TCP_FLAG_PSH) != 0,
			ACK:        (flags & TCP_FLAG_ACK) != 0,
			URG:        (flags & TCP_FLAG_URG) != 0,
			Window:     uint16(65535),
			Urgent:     0,
		}
		tcp.SetNetworkLayerForChecksum(&ip)

		layers := []gopacket.SerializableLayer{&ip, &tcp}
		if len(payload) > 0 {
			layers = append(layers, gopacket.Payload(payload))
		}

		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layers...); err != nil {
			return err
		}
	}
	return nil
}
