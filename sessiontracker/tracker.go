package sessiontracker

import (
	"log/slog"
	"sync"
	"time"

	"github.com/yuuki/ssh_session_exporter/utmp"
)

// EndedSession represents a session that has ended.
type EndedSession struct {
	utmp.Session
	Duration time.Duration
}

// SessionDelta represents changes between two utmp snapshots.
type SessionDelta struct {
	NewSessions   []utmp.Session
	EndedSessions []EndedSession
}

type sessionKey struct {
	user string
	tty  string
}

// Tracker tracks SSH session lifecycles by diffing utmp snapshots.
type Tracker struct {
	mu     sync.Mutex
	active map[sessionKey]utmp.Session
	now    func() time.Time // for testing
	logger *slog.Logger
}

func New(logger *slog.Logger) *Tracker {
	return &Tracker{
		active: make(map[sessionKey]utmp.Session),
		now:    time.Now,
		logger: logger,
	}
}

// Initialize populates the tracker with an initial set of sessions as baseline.
// These sessions are not counted as new connections. If they subsequently
// disappear from utmp, they are reported as ended sessions by UpdateSessions
// and counted as disconnections.
func (t *Tracker) Initialize(current []utmp.Session) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, s := range current {
		t.active[sessionKey{s.User, s.TTY}] = s
	}
	t.logger.Debug("baseline initialized", "sessions", len(current))
}

// UpdateSessions compares the current utmp snapshot with tracked state,
// returning newly connected and disconnected sessions.
func (t *Tracker) UpdateSessions(current []utmp.Session) SessionDelta {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	var delta SessionDelta

	currentSet := make(map[sessionKey]utmp.Session, len(current))
	for _, s := range current {
		currentSet[sessionKey{s.User, s.TTY}] = s
	}

	// Detect ended sessions (in active but not in current, or replaced by a new session on the same TTY).
	for key, tracked := range t.active {
		current, exists := currentSet[key]
		if !exists || current.LoginTime != tracked.LoginTime {
			duration := now.Sub(tracked.LoginTime)
			delta.EndedSessions = append(delta.EndedSessions, EndedSession{
				Session:  tracked,
				Duration: duration,
			})
			delete(t.active, key)
			t.logger.Debug("session ended",
				"user", tracked.User,
				"remote_ip", tracked.Host,
				"tty", tracked.TTY,
				"duration", duration,
			)
		}
	}

	// Detect new sessions (in current but not in active).
	for key, s := range currentSet {
		if _, exists := t.active[key]; !exists {
			t.active[key] = s
			delta.NewSessions = append(delta.NewSessions, s)
			t.logger.Debug("session started",
				"user", s.User,
				"remote_ip", s.Host,
				"tty", s.TTY,
			)
		}
	}

	return delta
}

func (t *Tracker) ActiveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.active)
}
