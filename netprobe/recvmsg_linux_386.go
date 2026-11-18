package netprobe

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func socketRecvmsg(fd int, msg *unix.Msghdr, flags int) (int, error) {
	// Linux 386 multiplexes socket operations through socketcall; 17 is recvmsg.
	args := [3]uintptr{uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(flags)}
	n, _, errno := unix.Syscall(unix.SYS_SOCKETCALL, 17, uintptr(unsafe.Pointer(&args[0])), 0)
	runtime.KeepAlive(msg)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}
