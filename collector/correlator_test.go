package collector

import (
	"testing"
	"time"
)

func TestCorrelator_RecordFailure(t *testing.T) {
	c := newSessionCorrelator(5 * time.Minute)
	c.RecordFailure(1001)
	c.RecordFailure(1001)
	c.RecordFailure(1001)

	count, _ := c.RecordAccept(1001, "alice", "10.0.0.1", time.Now())
	if count != 3 {
		t.Errorf("RecordAccept returned failure count %d, want 3", count)
	}
}

func TestCorrelator_RecordAcceptNoFailures(t *testing.T) {
	c := newSessionCorrelator(5 * time.Minute)
	count, _ := c.RecordAccept(2001, "alice", "10.0.0.1", time.Now())
	if count != 0 {
		t.Errorf("RecordAccept returned failure count %d, want 0", count)
	}
}

func TestCorrelator_ConsumeAccept(t *testing.T) {
	c := newSessionCorrelator(5 * time.Minute)
	acceptTime := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	c.RecordAccept(3001, "alice", "192.168.1.10", acceptTime)

	got, ok := c.ConsumeAccept("alice", "192.168.1.10")
	if !ok {
		t.Fatal("ConsumeAccept returned false, want true")
	}
	if !got.Equal(acceptTime) {
		t.Errorf("ConsumeAccept time = %v, want %v", got, acceptTime)
	}

	// Second consume should fail (FIFO depleted).
	_, ok = c.ConsumeAccept("alice", "192.168.1.10")
	if ok {
		t.Error("second ConsumeAccept should return false")
	}
}

func TestCorrelator_ConsumeAcceptNotFound(t *testing.T) {
	c := newSessionCorrelator(5 * time.Minute)
	_, ok := c.ConsumeAccept("unknown", "10.0.0.1")
	if ok {
		t.Error("ConsumeAccept for unknown user+IP should return false")
	}
}

func TestCorrelator_SessionBeforeAccept(t *testing.T) {
	c := newSessionCorrelator(5 * time.Minute)
	loginTime := time.Date(2026, 3, 27, 12, 0, 2, 0, time.UTC)
	acceptTime := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)

	// Session arrives first (no accept yet).
	c.RecordNewSession("alice", "192.168.1.10", loginTime)

	// ConsumeAccept should fail since no accept recorded.
	_, ok := c.ConsumeAccept("alice", "192.168.1.10")
	if ok {
		t.Fatal("ConsumeAccept should return false before accept is recorded")
	}

	// Accept arrives later — should resolve the pending session.
	// Use a different PID (simulates real-world privsep).
	failCount, setup := c.RecordAccept(9999, "alice", "192.168.1.10", acceptTime)
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
	c := newSessionCorrelator(5 * time.Minute)
	acceptTime := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)

	// Accept arrives first — no pending session, so no setup result.
	_, setup := c.RecordAccept(7001, "alice", "192.168.1.10", acceptTime)
	if setup != nil {
		t.Fatal("expected nil SetupResult when no pending session")
	}

	// ConsumeAccept should succeed.
	got, ok := c.ConsumeAccept("alice", "192.168.1.10")
	if !ok {
		t.Fatal("ConsumeAccept should succeed after RecordAccept")
	}
	if !got.Equal(acceptTime) {
		t.Errorf("ConsumeAccept time = %v, want %v", got, acceptTime)
	}
}

func TestCorrelator_FIFO_MultipleAccepts(t *testing.T) {
	c := newSessionCorrelator(5 * time.Minute)
	t1 := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 3, 27, 12, 0, 5, 0, time.UTC)

	c.RecordAccept(1001, "alice", "192.168.1.10", t1)
	c.RecordAccept(1002, "alice", "192.168.1.10", t2)

	// First consume returns oldest.
	got, ok := c.ConsumeAccept("alice", "192.168.1.10")
	if !ok || !got.Equal(t1) {
		t.Errorf("first ConsumeAccept = %v, want %v", got, t1)
	}

	// Second consume returns next.
	got, ok = c.ConsumeAccept("alice", "192.168.1.10")
	if !ok || !got.Equal(t2) {
		t.Errorf("second ConsumeAccept = %v, want %v", got, t2)
	}

	// Third consume fails.
	_, ok = c.ConsumeAccept("alice", "192.168.1.10")
	if ok {
		t.Error("third ConsumeAccept should return false")
	}
}

func TestCorrelator_FIFO_MultiplePendingSessions(t *testing.T) {
	c := newSessionCorrelator(5 * time.Minute)
	login1 := time.Date(2026, 3, 27, 12, 0, 2, 0, time.UTC)
	login2 := time.Date(2026, 3, 27, 12, 0, 7, 0, time.UTC)
	accept1 := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	accept2 := time.Date(2026, 3, 27, 12, 0, 5, 0, time.UTC)

	// Two sessions arrive before any accept.
	c.RecordNewSession("alice", "192.168.1.10", login1)
	c.RecordNewSession("alice", "192.168.1.10", login2)

	// First accept resolves oldest pending session.
	_, setup := c.RecordAccept(1001, "alice", "192.168.1.10", accept1)
	if setup == nil || setup.Duration != 2*time.Second {
		t.Errorf("first setup = %v, want 2s", setup)
	}

	// Second accept resolves next pending session.
	_, setup = c.RecordAccept(1002, "alice", "192.168.1.10", accept2)
	if setup == nil || setup.Duration != 2*time.Second {
		t.Errorf("second setup = %v, want 2s", setup)
	}
}

func TestCorrelator_Cleanup(t *testing.T) {
	c := newSessionCorrelator(1 * time.Millisecond)
	c.RecordFailure(5001)

	time.Sleep(5 * time.Millisecond)
	c.Cleanup()

	count, _ := c.RecordAccept(5001, "alice", "10.0.0.1", time.Now())
	if count != 0 {
		t.Errorf("after cleanup, failure count should be 0, got %d", count)
	}
}

func TestCorrelator_CleanupPendingSessions(t *testing.T) {
	c := newSessionCorrelator(1 * time.Millisecond)
	c.RecordNewSession("bob", "10.0.0.5", time.Now())

	time.Sleep(5 * time.Millisecond)
	c.Cleanup()

	// Accept after cleanup — pending session should be gone.
	_, setup := c.RecordAccept(8001, "bob", "10.0.0.5", time.Now())
	if setup != nil {
		t.Error("expected nil SetupResult after cleanup evicted pending session")
	}
}

func TestCorrelator_CleanupAccepts(t *testing.T) {
	c := newSessionCorrelator(1 * time.Millisecond)
	c.RecordAccept(1001, "alice", "10.0.0.1", time.Now())

	time.Sleep(5 * time.Millisecond)
	c.Cleanup()

	_, ok := c.ConsumeAccept("alice", "10.0.0.1")
	if ok {
		t.Error("expected ConsumeAccept to return false after cleanup evicted accept")
	}
}
