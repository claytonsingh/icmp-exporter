package main

type IcmpPacket struct {
	Type           byte   // type of message
	Code           byte   // type of sub code
	Checksum       uint16 // ones complement checksum of struct
	Identifier     uint16 // identifier
	SequenceNumber uint16 // sequence number
	Payload        []byte
}

func (packet IcmpPacket) Serialize4(buffer []byte) int {

	length := 8 + len(packet.Payload)
	nw := NewNetworkWriter(buffer)

	nw.WriteUint8(packet.Type)
	nw.WriteUint8(packet.Code)
	nw.WriteUint16(0)
	nw.WriteUint16(packet.Identifier)
	nw.WriteUint16(packet.SequenceNumber)
	nw.WriteBytes(packet.Payload)

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

	for true {
		var temp = xsum >> 16
		if temp == 0 {
			break
		}
		xsum = temp + (xsum & 0xFFFF)
	}

	return (uint16)(0xFFFF ^ xsum)
}

func (packet IcmpPacket) Serialize6(buffer []byte) int {

	length := 8 + len(packet.Payload)
	nw := NewNetworkWriter(buffer)

	nw.WriteUint8(packet.Type)
	nw.WriteUint8(packet.Code)
	nw.WriteUint16(0)
	nw.WriteUint16(packet.Identifier)
	nw.WriteUint16(packet.SequenceNumber)
	nw.WriteBytes(packet.Payload)

	//nw.Seek(2)
	//nw.WriteUint16(ComputeChecksum6(buffer, 0, length))

	return length
}
