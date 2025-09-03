package main

import (
	"bytes"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	icmpActiveProbes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "icmp_active_probes",
		Help: "The number of active probes",
	})
	tcpActiveProbes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "tcp_active_probes",
		Help: "The number of active TCP probes",
	})
)

type Pinger interface {
	SetProbes(probes []*PingProbe)
}

type Native struct {
	ICMPNative  *ICMPNative
	TCPNative   *TCPNative
	probeMutex  sync.Mutex
	probes      []*PingProbe
	interval    time.Duration
	minInterval time.Duration
	nextPacket  time.Time
}

func NewNative(hardware bool, iface4 string, iface6 string, timeout int, interval int, maxpps int, identifier int, minPort uint16, maxPort uint16) *Native {
	return &Native{
		ICMPNative:  NewICMPNative(hardware, iface4, iface6, timeout, uint16(identifier)),
		TCPNative:   NewTCPNative(hardware, iface4, iface6, timeout, uint16(identifier), minPort, maxPort),
		interval:    time.Duration(interval) * time.Millisecond,
		minInterval: time.Duration(float64(time.Second) / float64(maxpps)),
		nextPacket:  time.Now(),
	}
}

func (this *Native) Start() {
	this.ICMPNative.Start()
	this.TCPNative.Start()
	go this.transmitThread()
}

func (this *Native) SetProbes(probes []*PingProbe) {
	// copy probes to a new slice
	probesCopy := make([]*PingProbe, len(probes))
	copy(probesCopy, probes)

	// sort probes by IP
	sort.Slice(probesCopy, func(i, j int) bool {
		return bytes.Compare(probesCopy[i].IPAddress, probesCopy[j].IPAddress) < 0
	})

	// count the max number of probes with the same IP
	maxIPCount := 0
	icmpProbes := 0
	tcpProbes := 0
	{
		lastIP := net.IP{}
		ipCount := 0
		for _, probe := range probesCopy {
			if probe.TCPPort == 0 {
				icmpProbes++
			} else {
				tcpProbes++
			}
			if probe.IPAddress.Equal(lastIP) {
				ipCount++
			} else {
				if ipCount > maxIPCount {
					maxIPCount = ipCount
				}
				lastIP = probe.IPAddress
				ipCount = 1
			}
		}
		if ipCount > maxIPCount {
			maxIPCount = ipCount
		}
	}

	// Space out probes with the same IP to avoid congestion
	probesShuffled := make([]*PingProbe, len(probes))
	i := 0
	for x := range maxIPCount {
		for y := x; y < len(probesCopy); y += maxIPCount {
			probesShuffled[i] = probesCopy[y]
			i += 1
		}
	}

	this.probeMutex.Lock()
	icmpActiveProbes.Set(float64(icmpProbes))
	tcpActiveProbes.Set(float64(tcpProbes))
	this.probes = probesShuffled
	this.probeMutex.Unlock()
}

func (this *Native) transmitThread() {
	for {
		this.probeMutex.Lock()
		probes := this.probes
		this.probeMutex.Unlock()

		if len(probes) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}

		interpacketDuration := time.Duration(float64(this.interval) / float64(len(probes)))
		if interpacketDuration < this.minInterval {
			interpacketDuration = this.minInterval
		}

		this.ICMPNative.IncrementSequenceNumber()
		this.TCPNative.IncrementSequenceNumber()

		for _, probe := range probes {
			this.nextPacket = this.nextPacket.Add(interpacketDuration)

			now := time.Now()
			dt := this.nextPacket.Sub(now)

			if dt > 0 {
				time.Sleep(dt)
			} else if dt < time.Second {
				this.nextPacket = now
			} else if dt < time.Millisecond*-10 {
				this.nextPacket = now.Add(time.Millisecond * -10)
			}

			if probe.TCPPort == 0 {
				this.ICMPNative.Transmit(probe)
			} else {
				this.TCPNative.Transmit(probe)
			}
		}
	}
}

type PingProbe struct {
	IPAddress        net.IP
	TCPPort          uint16 // TCP destination port for SYN ping
	SentCount        int32
	RecvCount        int32
	RoundtripTotal   int64 // In microseconds
	RoundtripSqTotal int64 // In microseconds
	Results          DataBuff[PingResult]
	ResultLimit      int
	LastAccess       time.Time
	Mutex            sync.Mutex
}

func (this *PingProbe) AddSample(sample PingResult) {
	this.Mutex.Lock()

	// if we have sent many packets then reset all the counters to prevent loss of precision
	if this.SentCount >= 0x7F000000 {
		this.SentCount = 0
		this.RecvCount = 0
		this.RoundtripTotal = 0
		this.RoundtripSqTotal = 0
	}

	this.SentCount += 1
	this.ResultLimit += 1
	if this.ResultLimit > this.Results.Size {
		this.ResultLimit = this.Results.Size
	}

	this.Results.Append(sample)
	if sample.Success {
		this.RecvCount += 1
		this.RoundtripTotal += sample.RountripTime
		this.RoundtripSqTotal += sample.RountripTime * sample.RountripTime
	}
	this.Mutex.Unlock()
}

type PingResult struct {
	Success      bool
	RountripTime int64 // In microseconds
	Timestamp    time.Time
}
