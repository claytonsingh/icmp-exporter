package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

func GetDefaultRouteInterface() (string, error) {
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

		fields := strings.Fields(string(line))
		ifc := fields[0]
		ip := fields[1]
		netmask := fields[7]

		if ip == "00000000" && netmask == "00000000" {
			// default route
			return ifc, nil // interface name
		}
	}
	return "", errors.New("No default route")
}
