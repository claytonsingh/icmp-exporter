# What is icmp-exporter?
ICMP exporter for [prometheus](https://prometheus.io) that asynchronously sends pings to probe endpoints allowing the detection of path issues.

Leveraging hardware timestamping features provided by the network card, uncertainty accumulated by thread scheduling and the kernel is eliminated, allowing timestamps to the nearest microsecond.

The major difference from blackbox is that we use counters where possible and asynchronously send packets in the background. When a request to the probe endpoint is recieved data collection is started for that target sending a ping every `interval`. This background collection continues as long as the probe endpoint for that target is requested more than once every 10m.

# Command line
```
Usage of icmp-exporter:
  -drop
        Drop capabilities after starting.
  -hard
        Use hardware timestamping.
  -i-wont-be-evil
        Unlocks all other settings
  -interface4 string
        IPv4 interface to bind to. (default "auto")
  -interface6 string
        IPv6 interface to bind to. (default "auto")
  -interval int
        Interval in milliseconds. Minimum 10. Must be unlocked. (default 2000)
  -listen string
        ip and port to listen on. (default ":9116")
  -maxpps int
        Maximum packets per second. Minimum 1. Must be unlocked. (default 10000)
  -timeout int
        Timout in milliseconds. (default 3000)
```

# URL parameters
```
target
        The ip or hostname you want to ping
ip_version
        What version of ip you want to use when resolving dns records, defaults to 46
        4 for ipv4 only lookup
        6 for ipv6 only lookup
        46 for ipv4 lookup then ipv6
        64 for ipv6 lookup then ipv4
```

# Prometheus example configuration
```
scrape_configs:
  - job_name: 'Packet Loss Exporter'
    metrics_path: /probe
    relabel_configs:
    - target_label: __param_target
      source_labels: [__address__]
    - target_label: instance
      source_labels: [__address__]
    - target_label: __address__
      replacement: 127.0.0.1:9116
    static_configs:
    - targets:
      - example.com
```

# Network card support
This software requires some network card features here is how to check if your network interface is supported.

- Hardware timestamping requires: `SOF_TIMESTAMPING_TX_HARDWARE`, `SOF_TIMESTAMPING_RX_HARDWARE`, `HWTSTAMP_TX_ON`, and `HWTSTAMP_FILTER_ALL`
- Software timestamping requires: `SOF_TIMESTAMPING_TX_SOFTWARE`, and `SOF_TIMESTAMPING_RX_SOFTWARE`

```
# ethtool -T ens16
Time stamping parameters for ens16:
Capabilities:
        hardware-transmit     (SOF_TIMESTAMPING_TX_HARDWARE)
        software-transmit     (SOF_TIMESTAMPING_TX_SOFTWARE)
        hardware-receive      (SOF_TIMESTAMPING_RX_HARDWARE)
        software-receive      (SOF_TIMESTAMPING_RX_SOFTWARE)
        software-system-clock (SOF_TIMESTAMPING_SOFTWARE)
        hardware-raw-clock    (SOF_TIMESTAMPING_RAW_HARDWARE)
PTP Hardware Clock: 0
Hardware Transmit Timestamp Modes:
        off                   (HWTSTAMP_TX_OFF)
        on                    (HWTSTAMP_TX_ON)
Hardware Receive Filter Modes:
        none                  (HWTSTAMP_FILTER_NONE)
        all                   (HWTSTAMP_FILTER_ALL)
```

## Known network cards
| Card/Chipset        | Status Software    | Status Hardware    | Notes
|---------------------|--------------------|--------------------|--------
| Intel X550          | :heavy_check_mark: | :heavy_check_mark: | Tested
| Intel e1000         | :heavy_check_mark: | :x:                | Tested
| KVM Virtio          | :heavy_check_mark: | :x:                | Tested
| Vmware vmxnet3      | :x:                | :x:                | Needs driver support, use e1000
| Mellanox connectx-3 | :grey_question:    | :grey_question:    | Should work, not tested
| Mellanox connectx-4 | :grey_question:    | :grey_question:    | Should work, not tested
| Mellanox connectx-5 | :grey_question:    | :grey_question:    | Should work, not tested
| Mellanox connectx-6 | :grey_question:    | :grey_question:    | Should work, not tested

# Building
Assuming you have golang setup
```
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o bin/icmp-exporter-amd64 cmd/icmp-exporter/*.go
```
