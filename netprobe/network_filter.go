package netprobe

import (
	"errors"

	"golang.org/x/net/bpf"
	syscall "golang.org/x/sys/unix"
)

// BpfFilter represents a classic BPF filter program that can be applied to a socket
// https://riyazali.net/posts/berkeley-packet-filter-in-golang/
type BpfFilter []bpf.Instruction

// ApplyTo sets the filter on the provided file descriptor
func (filter BpfFilter) ApplyTo(fd int) (err error) {
	if len(filter) == 0 || len(filter) > 0xFFFF {
		return errors.New("bpf filter must contain between 1 and 65535 instructions")
	}

	f, e := bpf.Assemble(filter)
	if e != nil {
		return e
	}
	filters := make([]syscall.SockFilter, len(f))
	for i, instruction := range f {
		filters[i] = syscall.SockFilter{Code: instruction.Op, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K}
	}
	var program = syscall.SockFprog{
		Len:    uint16(len(f)),
		Filter: &filters[0],
	}
	return syscall.SetsockoptSockFprog(fd, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, &program)
}
