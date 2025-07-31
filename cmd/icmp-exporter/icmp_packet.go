package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IcmpPacket struct {
	Type           byte   // type of message
	Code           byte   // type of sub code
	Checksum       uint16 // ones complement checksum of struct
	Identifier     uint16 // identifier
	SequenceNumber uint16 // sequence number
	Payload        []byte
}

var icmp4TypeCode = layers.CreateICMPv4TypeCode(8, 0)
var icmp6TypeCode = layers.CreateICMPv6TypeCode(128, 0)

func IcmpSerialize(buf gopacket.SerializeBuffer, srcIP, dst net.IP, identifier uint16, sequenceNumber uint16, payload []byte) error {

	if IsIPv4(dst) {
		ip := layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    srcIP.To4(),
			DstIP:    dst.To4(),
			Flags:    layers.IPv4DontFragment,
			Protocol: layers.IPProtocolICMPv4,
		}
		icmp := layers.ICMPv4{
			TypeCode: icmp4TypeCode,
			Checksum: 0,
			Id:       identifier,
			Seq:      sequenceNumber,
		}
		payload := gopacket.Payload(payload)
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, &ip, &icmp, payload); err != nil {
			return err
		}
	} else {
		ip := layers.IPv6{
			Version:  6,
			HopLimit: 64,
			SrcIP:    srcIP.To16(),
			DstIP:    dst.To16(),

			NextHeader: layers.IPProtocolICMPv6,
		}
		icmp := layers.ICMPv6{
			TypeCode: icmp6TypeCode,
			Checksum: 0,
		}
		icmpecho := layers.ICMPv6Echo{
			Identifier: identifier,
			SeqNumber:  sequenceNumber,
		}
		payload := gopacket.Payload(payload)

		// Set the network layer for checksum calculation
		icmp.SetNetworkLayerForChecksum(&ip)

		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, &ip, &icmp, &icmpecho, payload); err != nil {
			return err
		}
	}
	return nil
}

func (this IcmpPacket) Serialize4(buffer []byte) int {

	length := 8 + len(this.Payload)
	nw := NewNetworkWriter(buffer)

	nw.WriteUint8(this.Type)
	nw.WriteUint8(this.Code)
	nw.WriteUint16(0)
	nw.WriteUint16(this.Identifier)
	nw.WriteUint16(this.SequenceNumber)
	nw.WriteBytes(this.Payload)

	nw.Seek(2)
	nw.WriteUint16(ComputeChecksum4(buffer))

	return length
}

func ComputeChecksum4(packet []byte) uint16 {
	// https://tools.ietf.org/html/rfc1071
	var xsum uint = 0
	count := len(packet) - 1

	// Sum up the 16-bits
	for i := 0; i < count; i += 2 {
		xsum += (uint(packet[i+0]) << 8) | uint(packet[i+1])
	}

	// Add left-over byte
	if (count & 1) == 0 {
		xsum += uint(packet[count])
	}

	xsum = (xsum >> 16) + (xsum & 0xFFFF)
	xsum = (xsum >> 16) + (xsum & 0xFFFF)

	return (uint16)(0xFFFF ^ xsum)
}

func (this IcmpPacket) Serialize6(buffer []byte) int {

	length := 8 + len(this.Payload)
	nw := NewNetworkWriter(buffer)

	nw.WriteUint8(this.Type)
	nw.WriteUint8(this.Code)
	nw.WriteUint16(0)
	nw.WriteUint16(this.Identifier)
	nw.WriteUint16(this.SequenceNumber)
	nw.WriteBytes(this.Payload)
	// For ipv6 do not set the checksum
	return length
}
