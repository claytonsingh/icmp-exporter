# What is prom-icmp?
Prom icmp is an ICMP poller for prometheus.

The major change from blackbox is that we use counters where possible and asynchronous send packets in the background.

# Command line
```
Usage of prom-icmp:
  -hard
        Use hardware timestamping
  -interface string
        Interface to bind to
  -listen string
        ip and port to listen on, defaults to :9116 (default ":9116")
```

# URL Arguments
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
