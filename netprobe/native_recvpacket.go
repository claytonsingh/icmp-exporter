package netprobe

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	syscall "golang.org/x/sys/unix"
)

func readSocket(sock int, data []byte, timestampType int) (ip net.IP, ndata int, ts int64) {
	for {
		var err error
		ip, ndata, ts, err = recvpacket(sock, data, 0, timestampType)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			panic(err)
		} else if ip != nil {
			return ip, ndata, ts
		}
	}
}

func readSocketErr(sock int, data []byte, timestampType int) (ip net.IP, ndata int, ts int64) {
	fds := []syscall.PollFd{{Fd: int32(sock), Events: syscall.POLLERR}}
	for {
		var err error
		ip, ndata, ts, err = recvpacket(sock, data, syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT, timestampType)
		if err == syscall.EINTR {
			continue
		} else if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			if _, err := syscall.Poll(fds, 2100); err != nil && err != syscall.EINTR {
				panic(err)
			}
			continue
		} else if err != nil {
			panic(err)
		} else if ndata == 0 {
			continue
		}
		return ip, ndata, ts
	}
}

// recvpacket receives both normal packets and transmit timestamp notifications.
// The error queue uses the same timestamp ancillary data as the receive queue.
func recvpacket(fd int, data []byte, flags int, timestampType int) (net.IP, int, int64, error) {
	var control [512]byte
	n, oobn, recvflags, from, err := syscall.Recvmsg(fd, data, control[:], flags)
	if err != nil {
		return nil, 0, 0, err
	}
	if recvflags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0 {
		return nil, 0, 0, fmt.Errorf("recvmsg: truncated packet or control data (flags %#x)", recvflags)
	}
	ts, err := packetTimestamp(control[:oobn], timestampType)
	if err != nil {
		return nil, 0, 0, err
	}
	var address net.IP
	switch from := from.(type) {
	case *syscall.SockaddrInet4:
		address = append(net.IP(nil), from.Addr[:]...)
	case *syscall.SockaddrInet6:
		address = append(net.IP(nil), from.Addr[:]...)
	}
	return address, n, ts, nil
}

func packetTimestamp(control []byte, timestampType int) (int64, error) {
	if timestampType < 0 || timestampType > 2 {
		return -1, fmt.Errorf("invalid timestamp slot %d", timestampType)
	}
	messages, err := syscall.ParseSocketControlMessage(control)
	if err != nil {
		return -1, fmt.Errorf("parse socket control messages: %w", err)
	}
	for _, message := range messages {
		if message.Header.Level != syscall.SOL_SOCKET {
			continue
		}
		var wordSize int
		switch message.Header.Type {
		case syscall.SO_TIMESTAMPING_OLD:
			wordSize = syscall.SizeofLong
		case syscall.SO_TIMESTAMPING_NEW:
			wordSize = 8
		default:
			continue
		}
		if len(message.Data) < 6*wordSize {
			return -1, fmt.Errorf("short timestamp control message: got %d bytes, need %d", len(message.Data), 6*wordSize)
		}
		stamp := message.Data[timestampType*2*wordSize:]
		var seconds, nanoseconds int64
		if wordSize == 4 {
			seconds = int64(int32(binary.NativeEndian.Uint32(stamp)))
			nanoseconds = int64(int32(binary.NativeEndian.Uint32(stamp[4:])))
		} else {
			seconds = int64(binary.NativeEndian.Uint64(stamp))
			nanoseconds = int64(binary.NativeEndian.Uint64(stamp[8:]))
		}
		if nanoseconds < 0 || nanoseconds >= 1_000_000_000 {
			return -1, fmt.Errorf("invalid timestamp nanoseconds %d", nanoseconds)
		}
		return (seconds*1_000_000 + nanoseconds/1_000) & 0x7FFFFFFFFFFFFFFF, nil
	}
	return -1, nil
}

func socketSetInterface(fd int, ifname string, flags int) error {
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifname); err != nil {
		return fmt.Errorf("bind socket to %s: %w", ifname, err)
	}
	info, err := syscall.IoctlGetEthtoolTsInfo(fd, ifname)
	if err != nil {
		return fmt.Errorf("get timestamp capabilities for %s: %w", ifname, err)
	}
	if info.So_timestamping&uint32(flags) != uint32(flags) {
		return fmt.Errorf("interface %s lacks required timestamp capabilities: have %#x, need %#x", ifname, info.So_timestamping, flags)
	}
	if flags&(syscall.SOF_TIMESTAMPING_RX_HARDWARE|syscall.SOF_TIMESTAMPING_TX_HARDWARE) == 0 {
		return nil
	}
	cfg, err := syscall.IoctlGetHwTstamp(fd, ifname)
	if err == nil && cfg.Tx_type == syscall.HWTSTAMP_TX_ON && cfg.Rx_filter == syscall.HWTSTAMP_FILTER_ALL {
		log.Printf("hardware timestamping already enabled on %s", ifname)
		return nil
	}
	cfg = &syscall.HwTstampConfig{Tx_type: syscall.HWTSTAMP_TX_ON, Rx_filter: syscall.HWTSTAMP_FILTER_ALL}
	if err := syscall.IoctlSetHwTstamp(fd, ifname, cfg); err != nil {
		return fmt.Errorf("enable hardware timestamping on %s: %w", ifname, err)
	}
	log.Printf("hardware timestamping on %s: tx_type %d requested, got %d; rx_filter %d requested, got %d",
		ifname, syscall.HWTSTAMP_TX_ON, cfg.Tx_type, syscall.HWTSTAMP_FILTER_ALL, cfg.Rx_filter)
	return nil
}

//lint:ignore ST1003 match c api
func socket_set_flags(fd int, ipversion int, so_timestamping_flags int, so_timestamp int, so_timestampns int) error {

	if so_timestamp > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP); err != nil {
			panic(err)
		} else {
			log.Printf("SO_TIMESTAMP:    %v %v\n", val, 1)
		}
	}

	if so_timestampns > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS); err != nil {
			panic(err)
		} else {
			log.Printf("SO_TIMESTAMPNS:  %v %v\n", val, 1)
		}
	}

	if so_timestamping_flags > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPING, so_timestamping_flags); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPING); err != nil {
			panic(err)
		} else {
			log.Printf("SO_TIMESTAMPING: %v %v\n", val, so_timestamping_flags)
		}
	}

	if false {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0); err != nil {
			panic(err)
		}

		if val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.IPV6_V6ONLY); err != nil {
			panic(err)
		} else {
			log.Printf("IPV6_V6ONLY: %v %v\n", val, 0)
		}
	}

	switch ipversion {
	case 4:
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			return err
		}
	case 6:
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_HDRINCL, 1); err != nil {
			return err
		}
	}

	return nil
}

//lint:ignore ST1003 match c api
func socket_set_recv_buffer(fd int, size int, name string) error {
	if size > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size); err != nil {
			return fmt.Errorf("set %s receive buffer: %w", name, err)
		}
	}
	actual, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return fmt.Errorf("read %s receive buffer: %w", name, err)
	}
	if size > 0 {
		log.Printf("%s receive buffer: requested %d bytes, effective %d bytes", name, size, actual)
	} else {
		log.Printf("%s receive buffer: using system default, effective %d bytes", name, actual)
	}
	return nil
}
