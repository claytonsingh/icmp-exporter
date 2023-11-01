package main

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/net/bpf"
	syscall "golang.org/x/sys/unix"
)

// https://riyazali.net/posts/berkeley-packet-filter-in-golang/
// Filter represents a classic BPF filter program that can be applied to a socket
type BpfFilter []bpf.Instruction

// ApplyTo sets the filter on the provided file descriptor
func (filter BpfFilter) ApplyTo(fd int) (err error) {
	if len(filter) > 0xFFFF {
		return errors.New("bpf filter is has too many instructions")
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	f, e := bpf.Assemble(filter)
	if e != nil {
		return e
	}
	pinner.Pin(&f)

	var program = syscall.SockFprog{
		Len:    uint16(len(f)),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&f[0])),
	}
	pinner.Pin(&program)

	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&program)), uintptr(syscall.SizeofSockFprog), 0); errno != 0 {
		return errno
	}

	return nil
}
