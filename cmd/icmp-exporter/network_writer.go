package main

type NetworkWriter struct {
	buffer []byte
	index  int
}

func NewNetworkWriter(buffer []byte) NetworkWriter {
	return NetworkWriter{buffer: buffer}
}

func (this *NetworkWriter) WriteUint8(value byte) {
	this.buffer[this.index] = value
	this.index += 1
}

func (this *NetworkWriter) WriteUint16(value uint16) {
	this.buffer[this.index+0] = (byte)(value >> 8)
	this.buffer[this.index+1] = (byte)(value >> 0)
	this.index += 2
}

func (this *NetworkWriter) WriteUint32(value uint32) {
	this.buffer[this.index+0] = (byte)(value >> 24)
	this.buffer[this.index+1] = (byte)(value >> 16)
	this.buffer[this.index+2] = (byte)(value >> 8)
	this.buffer[this.index+3] = (byte)(value >> 0)
	this.index += 4
}

func (this *NetworkWriter) WriteUint64(value uint64) {
	this.buffer[this.index+0] = (byte)(value >> 56)
	this.buffer[this.index+1] = (byte)(value >> 48)
	this.buffer[this.index+2] = (byte)(value >> 40)
	this.buffer[this.index+3] = (byte)(value >> 32)
	this.buffer[this.index+4] = (byte)(value >> 24)
	this.buffer[this.index+5] = (byte)(value >> 16)
	this.buffer[this.index+6] = (byte)(value >> 8)
	this.buffer[this.index+7] = (byte)(value >> 0)
	this.index += 8
}

func WriteUint64(buffer []byte, index int, value uint64) {
	buffer[index+0] = (byte)(value >> 56)
	buffer[index+1] = (byte)(value >> 48)
	buffer[index+2] = (byte)(value >> 40)
	buffer[index+3] = (byte)(value >> 32)
	buffer[index+4] = (byte)(value >> 24)
	buffer[index+5] = (byte)(value >> 16)
	buffer[index+6] = (byte)(value >> 8)
	buffer[index+7] = (byte)(value >> 0)
}

func (this *NetworkWriter) WriteBytes(value []byte) {
	copy(this.buffer[this.index:], value)
	this.index += len(value)
}

func (this *NetworkWriter) Seek(offset int) {
	this.index = offset
}
