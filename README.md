# What is icmp-exporter?
ICMP exporter for [prometheus](https://prometheus.io) efficiently detects path issues by asynchronously sending pings to probe endpoints. Utilizing network cards hardware timestamping features to eliminate scheduling and kernel-related uncertainties, achieving precision to the nearest microsecond.

The major difference from blackbox is that we use counters where possible and asynchronously send packets in the background. When a request to the probe endpoint is recieved data collection is started for that target sending a ping every `interval`. This background collection continues as long as the probe endpoint for that target is requested more than once every 10m.

## Features
- **ICMP Ping**: Traditional ICMP echo request/reply for network reachability testing
- **TCP SYN Ping**: TCP SYN packet probing for testing TCP connectivity and port reachability
- **Hardware Timestamping**: Microsecond precision using network card hardware features
- **IPv4/IPv6 Support**: Full dual-stack support for both ICMP and TCP
- **Prometheus Integration**: Clean metrics export with proper labeling

# Command line
```
Usage of icmp-exporter:
  -drop
        Drop capabilities after starting.
  -hard
        Use hardware timestamping.
  -i-wont-be-evil
        Unlocks advanced settings.
  -identifier int
        ICMP identifier between 0 and 65535. Must be unlocked. The possible options are:
        0 - Process pid (default)
        1 - Random
  -interface4 string
        IPv4 interface to bind to. If "auto" then the default route is used. (default "auto")
  -interface6 string
        IPv6 interface to bind to. If "auto" then the default route is used. (default "auto")
  -interval int
        ICMP interval in milliseconds. Minimum 10. Must be unlocked. (default 2000)
  -listen string
        Ip and port to listen on. (default ":9116")
  -maxpps int
        Maximum packets per second. Minimum 1. Must be unlocked. (default 10000)
  -timeout int
        ICMP timout in milliseconds. (default 3000)
```

## Running as non-root user
`CAP_NET_ADMIN` and `CAP_NET_RAW` are required when running as an unprivlaged user.
```
sudo setcap 'CAP_NET_ADMIN,CAP_NET_RAW=ep' /opt/icmp-exporter/icmp-exporter-linux-x64
```
```
/opt/icmp-exporter/icmp-exporter-linux-x64 -hard -drop -listen 127.0.0.1:9116
```

## Running with systemd
Copy [icmp-exporter.service](icmp-exporter.service) into `/etc/systemd/system/`.
```
systemctl start icmp-exporter.service
systemctl enable icmp-exporter.service
```

# URL parameters
```
target
        The ip or hostname you want to ping. Can be repeated.
ip_version
        What version of ip you want to use when resolving dns records, defaults to all.
        `4`: to resolve only ipv4 addresses
        `6`: to resolve only ipv6 addresses
        `all`: to resolve both ipv4 and ipv6 addresses
tcp_port
        TCP destination port to use for SYN ping. Can be repeated.
        Must be between 1 and 65535.
```

# Prometheus example configuration
ICMP
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

TCP
```
scrape_configs:
  - job_name: 'Packet Loss Exporter'
    metrics_path: /probe
    params:
      tcp_port: ['80', '443']
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

## Example probe requests for ICMP ping:
When `tcp_port` is not provided as a URL parameter, ICMP packets are sent.
```
# Probe with ICMP
http://localhost:9116/probe?target=example.com

# Probe multiple targets with ICMP
http://localhost:9116/probe?target=example.com&target=google.com
```

## Example probe requests for TCP SYN ping:
When `tcp_port` is provided as a URL parameter, TCP SYN packets are sent to the specified port.
```
# Probe with TCP port 22 (SSH)
http://localhost:9116/probe?target=example.com&tcp_port=22

# Probe with TCP port 80 and 443
http://localhost:9116/probe?target=example.com&tcp_port=80&tcp_port=443

# Probe multiple targets with TCP port 443
http://localhost:9116/probe?target=example.com&target=google.com&tcp_port=443

# Probe multiple targets with TCP port 80 and 443
http://localhost:9116/probe?target=example.com&target=google.com&tcp_port=80&tcp_port=443
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
| Card/Chipset                  | Status Software    | Status Hardware    | Notes
|-------------------------------|--------------------|--------------------|--------
| Intel X550                    | :heavy_check_mark: | :heavy_check_mark: | Tested
| Intel I350                    | :heavy_check_mark: | :heavy_check_mark: | Tested
| Intel e1000                   | :heavy_check_mark: | :x:                | Tested
| KVM Virtio                    | :heavy_check_mark: | :x:                | Tested
| Vmware vmxnet3                | :x:                | :x:                | Needs driver support, use e1000
| Mellanox connectx-3 (MT27500) | :heavy_check_mark: | :heavy_check_mark: | Tested, port flaps when timestamping is enabled. See [nvidia time-stamping](https://docs.nvidia.com/networking/display/mlnxofedv571020/time-stamping)
| Mellanox connectx-4           | :grey_question:    | :grey_question:    | Should work, not tested
| Mellanox connectx-5           | :grey_question:    | :grey_question:    | Should work, not tested
| Mellanox connectx-6           | :grey_question:    | :grey_question:    | Should work, not tested
| Microchip SMSC9512/9514       | :heavy_check_mark: | :x:                | Tested (Raspberry Pi Model B Rev 2)

# Building
Assuming you have golang setup
```
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o bin/icmp-exporter-amd64 ./cmd/icmp-exporter/
```

# Metrics
Tcp metrics are the same as ICMP except starting with `tcp_`

### Loss
Loss over the last `icmp_probe_samples_count`.
```
icmp_probe_loss_ratio{}
```

Loss over time
```
1 - increase(icmp_probe_packets_recv_total{}[10m]) / increase(icmp_probe_packets_sent_total{}[10m])
```

### Latency
Latency over the last `icmp_probe_samples_count`
```
icmp_probe_latency_seconds{}
```

Latency over time
```
increase(icmp_probe_latency_seconds_total{}[10m]) / increase(icmp_probe_packets_recv_total{}[10m])
```

### Standard deviation
Standard deviation over the last `icmp_probe_samples_count`
```
icmp_probe_standard_deviation_seconds{}
```

Standard deviation over time
```
sqrt(
  (increase(icmp_probe_latency_squared_seconds_total{}[10m]) / increase(icmp_probe_packets_recv_total{}[10m])) -
  (increase(icmp_probe_latency_seconds_total{}[10m])         / increase(icmp_probe_packets_recv_total{}[10m]))^2
)
```

### Meta
The `/metrics` endpoint provides various meta metrics for monitoring the exporter itself:

In addition to metrics starting with `icmp_` and `tcp_` there are metrics for the go runtime, http server, and process.

- `icmp_active_probes`: Number of currently active ICMP probes
- `icmp_packets_sent_total`: Total number of ICMP packets sent
- `icmp_packets_recv_total`: Total number of ICMP packets received
- `icmp_packets_error_total`: Total number of ICMP socket errors
- `tcp_active_probes`: Number of currently active TCP probes
- `tcp_packets_sent_total`: Total number of TCP SYN packets sent
- `tcp_packets_recv_total`: Total number of TCP SYN/ACK packets received
- `tcp_packets_error_total`: Total number of TCP socket errors
