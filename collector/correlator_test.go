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

	// Verify via RecordAccept which returns the failure count.
	count := c.RecordAccept(1001, time.Now())
	if count != 3 {
		t.Errorf("RecordAccept returned failure count %d, want 3", count)
	}
}

func TestCorrelator_RecordAcceptNoFailures(t *testing.T) {
	c := newPIDCorrelator(5 * time.Minute)
	count := c.RecordAccept(2001, time.Now())
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

	// Second consume should return false (entry deleted).
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
	// Only failures, no accept.
	c.RecordFailure(4001)
	_, ok := c.ConsumeAccept(4001)
	if ok {
		t.Error("ConsumeAccept should return false when no accept was recorded")
	}
}

func TestCorrelator_Cleanup(t *testing.T) {
	c := newPIDCorrelator(1 * time.Millisecond)
	c.RecordFailure(5001)

	// Wait for TTL to expire.
	time.Sleep(5 * time.Millisecond)
	c.Cleanup()

	// Entry should be gone.
	count := c.RecordAccept(5001, time.Now())
	if count != 0 {
		t.Errorf("after cleanup, failure count should be 0, got %d", count)
	}
}
