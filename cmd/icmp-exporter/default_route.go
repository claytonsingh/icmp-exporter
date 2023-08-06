package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

func GetDefaultRouterInterface4() (string, error) {
	const bufsize int = 4096

	const destinationAddress = "00000000"
	const destinationMask = "00000000"
	const gatewayFlags = '3'

	fd, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer fd.Close()

	br := bufio.NewReaderSize(fd, bufsize)
	for lineNum := 0; lineNum < 1024; lineNum++ {
		line, err := br.ReadSlice('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}

		// 0 - interface name
		// 1 - Destination
		// 2 - Gateway
		// 3 - Flags (https://github.com/torvalds/linux/blob/master/include/uapi/linux/route.h)
		// 4 - RefCnt
		// 5 - Use
		// 6 - Metric
		// 7 - Mask
		fields := strings.Fields(string(line))
		if fields[1] == destinationAddress && fields[7] == destinationMask && fields[3][3] == gatewayFlags {
			// default route
			return fields[0], nil // interface name
		}
	}
	return "", errors.New("No default route")
}

func GetDefaultRouterInterface6() (string, error) {
	const bufsize int = 4096

	const destinationAddress = "00000000000000000000000000000000"
	const destinationPrefix = "00"
	const gateway = "00000000000000000000000000000000"
	const gatewayFlags = '3'

	fd, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return "", err
	}
	defer fd.Close()

	br := bufio.NewReaderSize(fd, bufsize)
	for lineNum := 0; lineNum < 1024; lineNum++ {
		line, err := br.ReadSlice('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}

		// 0 - destination address
		// 1 - destination prefix length
		// 2 - source network
		// 3 - source prefix length
		// 4 - gateway
		// 5 - metric
		// 6 - reference counter
		// 7 - use counter
		// 8 - flags
		// 9 - interface name
		fields := strings.Fields(string(line))
		if fields[0] == destinationAddress && fields[1] == destinationPrefix && fields[4] != gateway && fields[8][7] == gatewayFlags {
			// default route
			return fields[9], nil // interface name
		}
	}
	return "", errors.New("No default route")
}
