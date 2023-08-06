# What is icmp-exporter?
ICMP exporter asynchronously sends pings to probe endpoints allowing the detection of path issues.

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

# Building
Assuming you have golang setup
```
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o bin/icmp-exporter-amd64 cmd/icmp-exporter/*.go
```
