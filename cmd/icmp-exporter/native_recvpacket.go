package main

/*
#include "native_recvpacket.h"
*/
import "C"
import (
	"net"
	"unsafe"
)

//lint:ignore ST1003 match c api
func recvpacket_v4(fd int, data []byte, recvmsg_flags int32, timestamp_type int) (address net.IP, result int, u_seconds int64) {
	var name [32]byte
	result = (int)(C.recvpacket_v4(C.int32_t(fd), (*C.uint8_t)(unsafe.Pointer(&name[0])), (*C.uint8_t)(unsafe.Pointer(&data[0])), C.uint32_t(len(data)), (*C.int64_t)(unsafe.Pointer(&u_seconds)), C.int32_t(recvmsg_flags), C.int32_t(timestamp_type)))

	switch int(name[0]) | (int(name[1]) << 8) {
	case C.AF_INET:
		address = make(net.IP, 4)
		copy(address[:], name[4:4+4])
	case C.AF_INET6:
		address = make(net.IP, 16)
		copy(address[:], name[8:8+16])
	default:
		address = make(net.IP, 0)
	}
	// fmt.Println("recvpacket_v4: ", address.String())
	return
}

//lint:ignore ST1003 match c api
func socket_set_ioctl_native(fd int, ifname string, flags int) int {
	// Cast a string to a 'C string'
	name := C.CString(ifname)
	defer C.free(unsafe.Pointer(name))

	return (int)(C.socket_set_ioctl(C.int32_t(fd), name, C.int32_t(flags)))
}
