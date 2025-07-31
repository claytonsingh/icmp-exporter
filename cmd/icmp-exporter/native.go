package main

import (
	"sync"
	"time"
)

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
	this.probeMutex.Lock()
	this.probes = probes
	this.probeMutex.Unlock()
}

func (this *Native) transmitThread() {
	for {
		this.probeMutex.Lock()
		probes := this.probes
		this.probeMutex.Unlock()

		activeProbes.Set(float64(len(probes)))
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
