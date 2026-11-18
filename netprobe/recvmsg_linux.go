//go:build linux && !386

package netprobe

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func socketRecvmsg(fd int, msg *unix.Msghdr, flags int) (int, error) {
	n, _, errno := unix.Syscall(unix.SYS_RECVMSG, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	runtime.KeepAlive(msg)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}
