package main

/*
#include "native_recvpacket.h"
*/
import "C"
import (
	"net"
	"unsafe"
)

func recvpacket_v4(fd int, data []byte, recvmsg_flags int32, timestamp_type int) (address net.IP, result int, u_seconds int64) {
	var name [32]byte
	result = (int)(C.recvpacket_v4(C.int32_t(fd), (*C.uint8_t)(unsafe.Pointer(&name[0])), (*C.uint8_t)(unsafe.Pointer(&data[0])), C.uint32_t(len(data)), (*C.int64_t)(unsafe.Pointer(&u_seconds)), C.int32_t(recvmsg_flags), C.int32_t(timestamp_type)))

	switch int(name[0]) | (int(name[1]) << 8) {
	case 0x0002:
		address = make(net.IP, 4)
		copy(address[:], name[4:4+4])
		break
	case 0x000A:
		address = make(net.IP, 16)
		copy(address[:], name[8:8+16])
		break
	default:
		address = make(net.IP, 0)
		break
	}
	// fmt.Println("recvpacket_v4: ", address.String())
	return
}

func socket_set_ioctl_native(fd int, ifname string, flags int) int {
	// Cast a string to a 'C string'
	name := C.CString(ifname)
	defer C.free(unsafe.Pointer(name))

	return (int)(C.socket_set_ioctl(C.int32_t(fd), name, C.int32_t(flags)))
}
