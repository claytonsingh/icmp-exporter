package netprobe

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"
)

var startTime = time.Now()

// Limiter is safe for concurrent use. Do not copy after use.
type Limiter struct {
	step     atomic.Int64
	burst    float64
	lastTime atomic.Int64
}

// NewLimiter spaces packets by interval. Burst is extra immediate packets after idle.
func NewLimiter(interval time.Duration, burst float64) (*Limiter, error) {
	if burst < 0 || math.IsNaN(burst) || math.IsInf(burst, 0) {
		return nil, fmt.Errorf("burst must be finite and non-negative")
	}
	l := &Limiter{burst: burst}
	if err := l.SetInterval(interval); err != nil {
		return nil, err
	}
	l.lastTime.Store(-1_000_000_000_000_000_000)
	return l, nil
}

// SetInterval changes the interval without resetting history.
func (this *Limiter) SetInterval(interval time.Duration) error {
	intervalN := interval.Nanoseconds()
	if interval <= 0 {
		return fmt.Errorf("interval must be greater than zero")
	}
	if float64(intervalN)*math.Max(1, this.burst+1) >= float64(math.MaxInt64) {
		return fmt.Errorf("interval or burst exceeds nanosecond scheduling range")
	}
	this.step.Store(intervalN)
	return nil
}

// Ntime returns monotonic elapsed nanoseconds.
func (this *Limiter) Ntime() int64 { return time.Since(startTime).Nanoseconds() }

// Acquire reserves one packet and waits until its send time. Callers get distinct slots; interval changes apply only to later reservations.
func (this *Limiter) Acquire() {
	now := this.Ntime()
	reservedN := this.reserveAt(now)
	if reservedN > now {
		if remaining := time.Duration(reservedN - this.Ntime()); remaining > 0 {
			time.Sleep(remaining)
		}
	}
}

// reserveAt debits one packet and returns its absolute send time.
func (this *Limiter) reserveAt(currentTime int64) int64 {
	step := this.step.Load()
	burstWindow := int64(float64(step) * this.burst)
	for {
		oldLastTime := this.lastTime.Load()
		reservedTime := max(currentTime-burstWindow, oldLastTime)
		if this.lastTime.CompareAndSwap(oldLastTime, reservedTime+step) {
			return reservedTime
		}
	}
}
