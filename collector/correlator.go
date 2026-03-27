package collector

import (
	"sync"
	"time"
)

type pidState struct {
	failedAttempts int
	acceptTime     time.Time
	createdAt      time.Time
}

// pidCorrelator tracks per-PID state to correlate auth log events with utmp sessions.
type pidCorrelator struct {
	mu   sync.Mutex
	pids map[int32]*pidState
	ttl  time.Duration
}

func newPIDCorrelator(ttl time.Duration) *pidCorrelator {
	return &pidCorrelator{
		pids: make(map[int32]*pidState),
		ttl:  ttl,
	}
}

// RecordFailure increments the failed attempt counter for a PID.
func (c *pidCorrelator) RecordFailure(pid int32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.pids[pid]
	if !ok {
		s = &pidState{createdAt: time.Now()}
		c.pids[pid] = s
	}
	s.failedAttempts++
}

// RecordAccept stores the acceptance timestamp for a PID and returns
// the number of prior failed attempts.
func (c *pidCorrelator) RecordAccept(pid int32, acceptTime time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.pids[pid]
	if !ok {
		s = &pidState{createdAt: time.Now()}
		c.pids[pid] = s
	}
	s.acceptTime = acceptTime
	return s.failedAttempts
}

// ConsumeAccept retrieves and removes the accept timestamp for a PID.
// Returns zero time and false if the PID has no recorded accept.
func (c *pidCorrelator) ConsumeAccept(pid int32) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.pids[pid]
	if !ok || s.acceptTime.IsZero() {
		return time.Time{}, false
	}
	t := s.acceptTime
	delete(c.pids, pid)
	return t, true
}

// Cleanup removes entries older than the configured TTL.
func (c *pidCorrelator) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-c.ttl)
	for pid, s := range c.pids {
		if s.createdAt.Before(cutoff) {
			delete(c.pids, pid)
		}
	}
}
