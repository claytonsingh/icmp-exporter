#!/bin/bash

go build -o "./bin/${PACKAGE_NAME}" -ldflags="${FLAGS}" ./cmd/icmp-exporter/
cp README.md ./bin
cp LICENSE ./bin

tar -czvf "${PACKAGE_NAME}.tar.gz" -C ./bin .
