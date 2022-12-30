package main

import (
	"sync"
)

type Signal struct {
	cond  *sync.Cond
	value uint64
}

func NewSignal() *Signal {
	return &Signal{
		cond: sync.NewCond(&sync.Mutex{}),
	}
}

func (this *Signal) Signal() {
	this.cond.L.Lock()
	this.value += 1
	this.cond.Broadcast()
	this.cond.L.Unlock()
}

func (this *Signal) GetWaiter(signaled bool) func() {
	var value uint64
	this.cond.L.Lock()
	value = this.value
	this.cond.L.Unlock()
	if signaled {
		value -= 1
	}
	return func() {
		this.cond.L.Lock()
		for {
			if value != this.value {
				value = this.value
				break
			}
			this.cond.Wait()
		}
		this.cond.L.Unlock()
	}
}
