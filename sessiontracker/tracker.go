package sessiontracker

import (
	"log/slog"
	"sync"
	"time"

	"github.com/yuuki/ssh_sesshon_exporter/utmp"
)

// TrackedSession holds information about a tracked session.
type TrackedSession struct {
	User      string
	RemoteIP  string
	TTY       string
	LoginTime time.Time
}

// EndedSession represents a session that has ended.
type EndedSession struct {
	TrackedSession
	Duration time.Duration
}

// SessionDelta represents changes between two utmp snapshots.
type SessionDelta struct {
	NewSessions   []TrackedSession
	EndedSessions []EndedSession
}

// sessionKey uniquely identifies a session.
func sessionKey(user, tty string) string {
	return user + ":" + tty
}

// Tracker tracks SSH session lifecycles by diffing utmp snapshots.
type Tracker struct {
	mu     sync.Mutex
	active map[string]TrackedSession // key: "user:tty"
	now    func() time.Time         // for testing
	logger *slog.Logger
}

// New creates a new Tracker.
func New(logger *slog.Logger) *Tracker {
	return &Tracker{
		active: make(map[string]TrackedSession),
		now:    time.Now,
		logger: logger,
	}
}

// UpdateSessions compares the current utmp snapshot with tracked state,
// returning newly connected and disconnected sessions.
func (t *Tracker) UpdateSessions(current []utmp.Session) SessionDelta {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	var delta SessionDelta

	// Build set of current session keys.
	currentSet := make(map[string]utmp.Session, len(current))
	for _, s := range current {
		key := sessionKey(s.User, s.TTY)
		currentSet[key] = s
	}

	// Detect ended sessions (in active but not in current).
	for key, tracked := range t.active {
		if _, exists := currentSet[key]; !exists {
			duration := now.Sub(tracked.LoginTime)
			delta.EndedSessions = append(delta.EndedSessions, EndedSession{
				TrackedSession: tracked,
				Duration:       duration,
			})
			delete(t.active, key)
			t.logger.Debug("session ended",
				"user", tracked.User,
				"remote_ip", tracked.RemoteIP,
				"tty", tracked.TTY,
				"duration", duration,
			)
		}
	}

	// Detect new sessions (in current but not in active).
	for key, s := range currentSet {
		if _, exists := t.active[key]; !exists {
			tracked := TrackedSession{
				User:      s.User,
				RemoteIP:  s.Host,
				TTY:       s.TTY,
				LoginTime: s.LoginTime,
			}
			t.active[key] = tracked
			delta.NewSessions = append(delta.NewSessions, tracked)
			t.logger.Debug("session started",
				"user", s.User,
				"remote_ip", s.Host,
				"tty", s.TTY,
			)
		}
	}

	return delta
}

// ActiveCount returns the number of currently tracked sessions.
func (t *Tracker) ActiveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.active)
}
