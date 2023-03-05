package main

import (
	"syscall"
	"unsafe"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// https://riyazali.net/posts/berkeley-packet-filter-in-golang/
// Filter represents a classic BPF filter program that can be applied to a socket
type BpfFilter []bpf.Instruction
type PcapFilter []pcap.BPFInstruction

// ApplyTo sets the filter on the provided file descriptor
func (filter BpfFilter) ApplyTo(fd int) (err error) {
	f, e := bpf.Assemble(filter)
	if e != nil {
		return e
	}

	var program = unix.SockFprog{
		Len:    uint16(len(f)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&f[0])),
	}
	var b = (*[unix.SizeofSockFprog]byte)(unsafe.Pointer(&program))[:unix.SizeofSockFprog]

	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0); errno != 0 {
		return errno
	}

	return nil
}

// ApplyTo sets the filter on the provided file descriptor
func (filter PcapFilter) ApplyTo(fd int) (err error) {
	var program = unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
	}
	var b = (*[unix.SizeofSockFprog]byte)(unsafe.Pointer(&program))[:unix.SizeofSockFprog]

	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0); errno != 0 {
		return errno
	}

	return nil
}

func SetBerkeleyPacketFilter(fd int, linkType layers.LinkType, filter string) (err error) {
	if f, err := pcap.CompileBPFFilter(linkType, 4096, filter); err != nil {
		return err
	} else if err := PcapFilter(f).ApplyTo(fd); err != nil {
		return err
	}
	return nil
}
