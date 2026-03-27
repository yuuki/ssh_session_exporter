package collector

import (
	"testing"
	"time"
)

func TestCorrelator_RecordFailure(t *testing.T) {
	c := newPIDCorrelator(5 * time.Minute)
	c.RecordFailure(1001)
	c.RecordFailure(1001)
	c.RecordFailure(1001)

	count, _ := c.RecordAccept(1001, time.Now())
	if count != 3 {
		t.Errorf("RecordAccept returned failure count %d, want 3", count)
	}
}

func TestCorrelator_RecordAcceptNoFailures(t *testing.T) {
	c := newPIDCorrelator(5 * time.Minute)
	count, _ := c.RecordAccept(2001, time.Now())
	if count != 0 {
		t.Errorf("RecordAccept returned failure count %d, want 0", count)
	}
}

func TestCorrelator_ConsumeAccept(t *testing.T) {
	c := newPIDCorrelator(5 * time.Minute)
	acceptTime := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	c.RecordAccept(3001, acceptTime)

	got, ok := c.ConsumeAccept(3001)
	if !ok {
		t.Fatal("ConsumeAccept returned false, want true")
	}
	if !got.Equal(acceptTime) {
		t.Errorf("ConsumeAccept time = %v, want %v", got, acceptTime)
	}

	_, ok = c.ConsumeAccept(3001)
	if ok {
		t.Error("second ConsumeAccept should return false")
	}
}

func TestCorrelator_ConsumeAcceptNotFound(t *testing.T) {
	c := newPIDCorrelator(5 * time.Minute)
	_, ok := c.ConsumeAccept(9999)
	if ok {
		t.Error("ConsumeAccept for unknown PID should return false")
	}
}

func TestCorrelator_ConsumeAcceptNoAcceptRecorded(t *testing.T) {
	c := newPIDCorrelator(5 * time.Minute)
	c.RecordFailure(4001)
	_, ok := c.ConsumeAccept(4001)
	if ok {
		t.Error("ConsumeAccept should return false when no accept was recorded")
	}
}

func TestCorrelator_Cleanup(t *testing.T) {
	c := newPIDCorrelator(1 * time.Millisecond)
	c.RecordFailure(5001)

	time.Sleep(5 * time.Millisecond)
	c.Cleanup()

	count, _ := c.RecordAccept(5001, time.Now())
	if count != 0 {
		t.Errorf("after cleanup, failure count should be 0, got %d", count)
	}
}

// TestCorrelator_SessionBeforeAccept verifies that when a utmp session
// is detected before the auth log accept arrives, the setup duration
// is resolved retroactively when RecordAccept is called.
func TestCorrelator_SessionBeforeAccept(t *testing.T) {
	c := newPIDCorrelator(5 * time.Minute)
	loginTime := time.Date(2026, 3, 27, 12, 0, 2, 0, time.UTC)
	acceptTime := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)

	// Session arrives first (no accept yet).
	c.RecordNewSession(6001, "alice", loginTime)

	// ConsumeAccept should fail since no accept recorded.
	_, ok := c.ConsumeAccept(6001)
	if ok {
		t.Fatal("ConsumeAccept should return false before accept is recorded")
	}

	// Accept arrives later — should resolve the pending session.
	failCount, setup := c.RecordAccept(6001, acceptTime)
	if failCount != 0 {
		t.Errorf("failCount = %d, want 0", failCount)
	}
	if setup == nil {
		t.Fatal("expected non-nil SetupResult")
	}
	if setup.User != "alice" {
		t.Errorf("setup.User = %q, want %q", setup.User, "alice")
	}
	wantDuration := 2 * time.Second
	if setup.Duration != wantDuration {
		t.Errorf("setup.Duration = %v, want %v", setup.Duration, wantDuration)
	}
}

func TestCorrelator_AcceptBeforeSession(t *testing.T) {
	c := newPIDCorrelator(5 * time.Minute)
	acceptTime := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)

	// Accept arrives first — no pending session, so no setup result.
	_, setup := c.RecordAccept(7001, acceptTime)
	if setup != nil {
		t.Fatal("expected nil SetupResult when no pending session")
	}

	// ConsumeAccept should succeed.
	got, ok := c.ConsumeAccept(7001)
	if !ok {
		t.Fatal("ConsumeAccept should succeed after RecordAccept")
	}
	if !got.Equal(acceptTime) {
		t.Errorf("ConsumeAccept time = %v, want %v", got, acceptTime)
	}
}

func TestCorrelator_CleanupPendingSessions(t *testing.T) {
	c := newPIDCorrelator(1 * time.Millisecond)
	c.RecordNewSession(8001, "bob", time.Now())

	time.Sleep(5 * time.Millisecond)
	c.Cleanup()

	// Accept after cleanup — pending session should be gone.
	_, setup := c.RecordAccept(8001, time.Now())
	if setup != nil {
		t.Error("expected nil SetupResult after cleanup evicted pending session")
	}
}
