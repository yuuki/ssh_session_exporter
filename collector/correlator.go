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

type pendingSession struct {
	user      string
	loginTime time.Time
}

// SetupResult is returned when an accept matches a pending session (or vice versa).
type SetupResult struct {
	User     string
	Duration time.Duration
}

type pidCorrelator struct {
	mu              sync.Mutex
	pids            map[int32]*pidState
	pendingSessions map[int32]pendingSession
	ttl             time.Duration
}

func newPIDCorrelator(ttl time.Duration) *pidCorrelator {
	return &pidCorrelator{
		pids:            make(map[int32]*pidState),
		pendingSessions: make(map[int32]pendingSession),
		ttl:             ttl,
	}
}

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

// RecordAccept stores the accept timestamp and returns the number of prior
// failed attempts. If a pending session exists for this PID, setup is non-nil.
func (c *pidCorrelator) RecordAccept(pid int32, acceptTime time.Time) (failCount int, setup *SetupResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.pids[pid]
	if !ok {
		s = &pidState{createdAt: time.Now()}
		c.pids[pid] = s
	}
	s.acceptTime = acceptTime
	failCount = s.failedAttempts

	if ps, ok := c.pendingSessions[pid]; ok {
		d := ps.loginTime.Sub(acceptTime)
		if d >= 0 {
			setup = &SetupResult{User: ps.user, Duration: d}
		}
		delete(c.pendingSessions, pid)
		delete(c.pids, pid)
	}

	return failCount, setup
}

// ConsumeAccept retrieves and removes the accept timestamp for a PID.
// Returns false if the PID has no recorded accept.
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

// RecordNewSession parks a new utmp session whose accept hasn't arrived yet.
func (c *pidCorrelator) RecordNewSession(pid int32, user string, loginTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingSessions[pid] = pendingSession{user: user, loginTime: loginTime}
}

func (c *pidCorrelator) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-c.ttl)
	for pid, s := range c.pids {
		if s.createdAt.Before(cutoff) {
			delete(c.pids, pid)
		}
	}
	for pid, ps := range c.pendingSessions {
		if ps.loginTime.Before(cutoff) {
			delete(c.pendingSessions, pid)
		}
	}
}
