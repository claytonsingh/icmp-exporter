package main

import (
	"bytes"
	"net"
)

func IsIPv4(address net.IP) bool {
	return len(address) == 4 || (len(address) == 16 && bytes.HasPrefix(address, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}))
}

func IsIPv6(address net.IP) bool {
	return len(address) == 16 && !bytes.HasPrefix(address, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF})
}

func Ipv6ToBytes(address net.IP) [16]byte {
	var ip [16]byte
	copy(ip[:], address.To16()[:])
	return ip
}

func Ipv4ToBytes(address net.IP) [4]byte {
	var ip [4]byte
	copy(ip[:], address.To4()[:])
	return ip
}
