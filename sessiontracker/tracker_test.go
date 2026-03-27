package sessiontracker

import (
	"log/slog"
	"testing"
	"time"

	"github.com/yuuki/ssh_session_exporter/utmp"
)

func newTestTracker(now time.Time) *Tracker {
	t := New(slog.Default())
	t.now = func() time.Time { return now }
	return t
}

func TestInitialize(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	tracker := newTestTracker(now)

	sessions := []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now.Add(-10 * time.Minute)},
		{User: "bob", TTY: "pts/1", Host: "10.0.0.5", LoginTime: now.Add(-5 * time.Minute)},
	}

	tracker.Initialize(sessions)

	if tracker.ActiveCount() != 2 {
		t.Fatalf("expected 2 active sessions after Initialize, got %d", tracker.ActiveCount())
	}

	// UpdateSessions with the same set should produce no delta.
	delta := tracker.UpdateSessions(sessions)
	if len(delta.NewSessions) != 0 {
		t.Errorf("expected 0 new sessions, got %d", len(delta.NewSessions))
	}
	if len(delta.EndedSessions) != 0 {
		t.Errorf("expected 0 ended sessions, got %d", len(delta.EndedSessions))
	}
}

func TestUpdateSessions_NewSessions(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	tracker := newTestTracker(now)

	sessions := []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now.Add(-10 * time.Minute)},
		{User: "bob", TTY: "pts/1", Host: "10.0.0.5", LoginTime: now.Add(-5 * time.Minute)},
	}

	delta := tracker.UpdateSessions(sessions)

	if len(delta.NewSessions) != 2 {
		t.Fatalf("expected 2 new sessions, got %d", len(delta.NewSessions))
	}
	if len(delta.EndedSessions) != 0 {
		t.Fatalf("expected 0 ended sessions, got %d", len(delta.EndedSessions))
	}
	if tracker.ActiveCount() != 2 {
		t.Fatalf("expected 2 active sessions, got %d", tracker.ActiveCount())
	}
}

func TestUpdateSessions_EndedSessions(t *testing.T) {
	loginTime := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	tracker := newTestTracker(now)

	// First: two sessions active.
	sessions := []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: loginTime},
		{User: "bob", TTY: "pts/1", Host: "10.0.0.5", LoginTime: loginTime},
	}
	tracker.UpdateSessions(sessions)

	// Second: only alice remains.
	sessions = []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: loginTime},
	}
	delta := tracker.UpdateSessions(sessions)

	if len(delta.NewSessions) != 0 {
		t.Fatalf("expected 0 new sessions, got %d", len(delta.NewSessions))
	}
	if len(delta.EndedSessions) != 1 {
		t.Fatalf("expected 1 ended session, got %d", len(delta.EndedSessions))
	}

	ended := delta.EndedSessions[0]
	if ended.User != "bob" {
		t.Errorf("expected ended user bob, got %s", ended.User)
	}
	expectedDuration := now.Sub(loginTime)
	if ended.Duration != expectedDuration {
		t.Errorf("expected duration %v, got %v", expectedDuration, ended.Duration)
	}
	if tracker.ActiveCount() != 1 {
		t.Fatalf("expected 1 active session, got %d", tracker.ActiveCount())
	}
}

func TestUpdateSessions_NoChange(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	tracker := newTestTracker(now)

	sessions := []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now},
	}

	tracker.UpdateSessions(sessions)
	delta := tracker.UpdateSessions(sessions)

	if len(delta.NewSessions) != 0 {
		t.Errorf("expected 0 new sessions, got %d", len(delta.NewSessions))
	}
	if len(delta.EndedSessions) != 0 {
		t.Errorf("expected 0 ended sessions, got %d", len(delta.EndedSessions))
	}
}

func TestUpdateSessions_AllDisconnect(t *testing.T) {
	loginTime := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	tracker := newTestTracker(now)

	sessions := []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: loginTime},
	}
	tracker.UpdateSessions(sessions)

	// All sessions gone.
	delta := tracker.UpdateSessions(nil)

	if len(delta.EndedSessions) != 1 {
		t.Fatalf("expected 1 ended session, got %d", len(delta.EndedSessions))
	}
	if tracker.ActiveCount() != 0 {
		t.Fatalf("expected 0 active sessions, got %d", tracker.ActiveCount())
	}
}

func TestUpdateSessions_SessionReplacement(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	tracker := newTestTracker(now)

	// alice on pts/0
	sessions := []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now},
	}
	tracker.UpdateSessions(sessions)

	// bob replaces alice on pts/0
	tracker.now = func() time.Time { return now.Add(30 * time.Minute) }
	sessions = []utmp.Session{
		{User: "bob", TTY: "pts/0", Host: "10.0.0.5", LoginTime: now.Add(30 * time.Minute)},
	}
	delta := tracker.UpdateSessions(sessions)

	if len(delta.EndedSessions) != 1 {
		t.Fatalf("expected 1 ended session, got %d", len(delta.EndedSessions))
	}
	if delta.EndedSessions[0].User != "alice" {
		t.Errorf("expected alice to end, got %s", delta.EndedSessions[0].User)
	}
	if len(delta.NewSessions) != 1 {
		t.Fatalf("expected 1 new session, got %d", len(delta.NewSessions))
	}
	if delta.NewSessions[0].User != "bob" {
		t.Errorf("expected bob to start, got %s", delta.NewSessions[0].User)
	}
}
