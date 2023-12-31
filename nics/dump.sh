#!/bin/bash
set +xeo pipefail

lshw -c network -json | jq 'map(select([..] | any(.logicalname? == $name))) | walk(del(.ip)? // .)' --arg name "$1"
ethtool -T "$1"
