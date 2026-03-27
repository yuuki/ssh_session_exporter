package collector

import (
	"sync"
	"time"
)

type correlationKey struct {
	user     string
	remoteIP string
}

type pidState struct {
	failedAttempts int
	createdAt      time.Time
}

type acceptEntry struct {
	timestamp time.Time
	createdAt time.Time
}

type pendingSessionEntry struct {
	loginTime time.Time
}

// SetupResult is returned when an accept matches a pending session (or vice versa).
type SetupResult struct {
	User     string
	Duration time.Duration
}

// sessionCorrelator tracks two independent concerns:
//   - PID-based failure counting (auth.log internal — same PID for failures and success)
//   - {user, remoteIP} FIFO queue matching for login setup timing (cross auth.log/utmp)
type sessionCorrelator struct {
	mu              sync.Mutex
	pids            map[int32]*pidState
	accepts         map[correlationKey][]acceptEntry
	pendingSessions map[correlationKey][]pendingSessionEntry
	ttl             time.Duration
}

func newSessionCorrelator(ttl time.Duration) *sessionCorrelator {
	return &sessionCorrelator{
		pids:            make(map[int32]*pidState),
		accepts:         make(map[correlationKey][]acceptEntry),
		pendingSessions: make(map[correlationKey][]pendingSessionEntry),
		ttl:             ttl,
	}
}

func (c *sessionCorrelator) RecordFailure(pid int32) {
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
// failed attempts for this PID. If a pending session exists for {user, remoteIP},
// setup is non-nil (FIFO: oldest pending session is consumed).
func (c *sessionCorrelator) RecordAccept(pid int32, user, remoteIP string, acceptTime time.Time) (failCount int, setup *SetupResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// PID-based failure counting.
	s, ok := c.pids[pid]
	if !ok {
		s = &pidState{createdAt: time.Now()}
		c.pids[pid] = s
	}
	failCount = s.failedAttempts
	delete(c.pids, pid)

	// {user, remoteIP} FIFO matching for login setup timing.
	key := correlationKey{user, remoteIP}
	if queue := c.pendingSessions[key]; len(queue) > 0 {
		ps := queue[0]
		d := ps.loginTime.Sub(acceptTime)
		if d >= 0 {
			setup = &SetupResult{User: user, Duration: d}
		}
		if len(queue) == 1 {
			delete(c.pendingSessions, key)
		} else {
			c.pendingSessions[key] = queue[1:]
		}
		return failCount, setup
	}

	// No pending session — store accept for later ConsumeAccept.
	c.accepts[key] = append(c.accepts[key], acceptEntry{
		timestamp: acceptTime,
		createdAt: time.Now(),
	})
	return failCount, nil
}

// ConsumeAccept dequeues the oldest accept timestamp for {user, remoteIP}.
// Returns false if no accept has been recorded.
func (c *sessionCorrelator) ConsumeAccept(user, remoteIP string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := correlationKey{user, remoteIP}
	queue := c.accepts[key]
	if len(queue) == 0 {
		return time.Time{}, false
	}
	entry := queue[0]
	if len(queue) == 1 {
		delete(c.accepts, key)
	} else {
		c.accepts[key] = queue[1:]
	}
	return entry.timestamp, true
}

// RecordNewSession parks a new utmp session whose accept hasn't arrived yet.
func (c *sessionCorrelator) RecordNewSession(user, remoteIP string, loginTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := correlationKey{user, remoteIP}
	c.pendingSessions[key] = append(c.pendingSessions[key], pendingSessionEntry{loginTime: loginTime})
}

func (c *sessionCorrelator) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-c.ttl)

	for pid, s := range c.pids {
		if s.createdAt.Before(cutoff) {
			delete(c.pids, pid)
		}
	}

	for key, queue := range c.accepts {
		i := 0
		for i < len(queue) && queue[i].createdAt.Before(cutoff) {
			i++
		}
		if i == len(queue) {
			delete(c.accepts, key)
		} else if i > 0 {
			c.accepts[key] = queue[i:]
		}
	}

	for key, queue := range c.pendingSessions {
		i := 0
		for i < len(queue) && queue[i].loginTime.Before(cutoff) {
			i++
		}
		if i == len(queue) {
			delete(c.pendingSessions, key)
		} else if i > 0 {
			c.pendingSessions[key] = queue[i:]
		}
	}
}
