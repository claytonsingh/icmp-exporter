package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

func GetDefaultRouterInterface4() (string, error) {
	var bufsize int = 4096

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
		if fields[1] == "00000000" && fields[7] == "00000000" && fields[3][3] == '3' {
			// default route
			return fields[0], nil // interface name
		}
	}
	return "", errors.New("No default route")
}

func GetDefaultRouterInterface6() (string, error) {
	var bufsize int = 4096

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
		if fields[0] == "00000000000000000000000000000000" && fields[1] == "00" && fields[4] != "00000000000000000000000000000000" && fields[8][7] == '3' {
			// default route
			return fields[9], nil // interface name
		}
	}
	return "", errors.New("No default route")
}
