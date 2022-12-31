package main

func ReadUInt64(buffer []byte, index int) uint64 {
	var val uint64
	val |= uint64(buffer[index+0]) << (7 * 8)
	val |= uint64(buffer[index+1]) << (6 * 8)
	val |= uint64(buffer[index+2]) << (5 * 8)
	val |= uint64(buffer[index+3]) << (4 * 8)
	val |= uint64(buffer[index+4]) << (3 * 8)
	val |= uint64(buffer[index+5]) << (2 * 8)
	val |= uint64(buffer[index+6]) << (1 * 8)
	val |= uint64(buffer[index+7]) << (0 * 8)
	return val
}

// func main() {
// 	data := make([]byte, 10)
// 	for i := 0; i < 64; i++ {
// 		WriteUint64(data, 0, 1<<i)
// 		val := ReadUInt64(data, 0)
// 		fmt.Println(data, uint64(1<<i) == val)
// 	}
// }
