package main

type NetworkWriter struct {
	m_buffer []byte
	m_index  int
}

func NewNetworkWriter(buffer []byte) NetworkWriter {
	return NetworkWriter{m_buffer: buffer}
}

func (nw *NetworkWriter) WriteUint8(value byte) {
	nw.m_buffer[nw.m_index] = value
	nw.m_index += 1
}

func (nw *NetworkWriter) WriteUint16(value uint16) {
	nw.m_buffer[nw.m_index+0] = (byte)(value >> 8)
	nw.m_buffer[nw.m_index+1] = (byte)(value >> 0)
	nw.m_index += 2
}

func (nw *NetworkWriter) WriteUint64(value uint64) {
	nw.m_buffer[nw.m_index+0] = (byte)(value >> 56)
	nw.m_buffer[nw.m_index+1] = (byte)(value >> 48)
	nw.m_buffer[nw.m_index+2] = (byte)(value >> 40)
	nw.m_buffer[nw.m_index+3] = (byte)(value >> 32)
	nw.m_buffer[nw.m_index+4] = (byte)(value >> 24)
	nw.m_buffer[nw.m_index+5] = (byte)(value >> 16)
	nw.m_buffer[nw.m_index+6] = (byte)(value >> 8)
	nw.m_buffer[nw.m_index+7] = (byte)(value >> 0)
	nw.m_index += 8
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

func (nw *NetworkWriter) WriteBytes(value []byte) {
	copy(nw.m_buffer[nw.m_index:], value)
	nw.m_index += len(value)
}

func (nw *NetworkWriter) Seek(offset int) {
	nw.m_index = offset
}
