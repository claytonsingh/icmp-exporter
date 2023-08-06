package main

type IcmpPacket struct {
	Type           byte   // type of message
	Code           byte   // type of sub code
	Checksum       uint16 // ones complement checksum of struct
	Identifier     uint16 // identifier
	SequenceNumber uint16 // sequence number
	Payload        []byte
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
	nw.WriteUint16(ComputeChecksum4(buffer, 0, length))

	return length
}

func ComputeChecksum4(packet []byte, index int, count int) uint16 {
	// https://tools.ietf.org/html/rfc1071
	var xsum uint = 0

	// Sum up the 16-bits
	for i := 0; i < count/2; i++ {
		xsum += (uint(packet[index+i*2]) << 8) | uint(packet[index+i*2+1])
	}

	// Pad if necessary
	if (count % 2) != 0 {
		xsum += uint(packet[index+count-1])
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
