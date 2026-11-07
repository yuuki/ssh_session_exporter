package collector

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"sync"
	"sync/atomic"
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

func TestCorrelator_CleanupEvictsOnlyTheExpiredHeadOfEachQueue(t *testing.T) {
	c := newSessionCorrelator(5 * time.Minute)
	// Far from the cutoff on both sides, so the moment Cleanup reads the
	// clock does not matter.
	stale := time.Now().Add(-time.Hour)
	fresh := time.Now().Add(time.Hour)
	ts := func(sec int) time.Time { return time.Date(2026, 3, 27, 12, 0, sec, 0, time.UTC) }

	c.pids[1] = &pidState{failedAttempts: 1, createdAt: stale}
	c.pids[2] = &pidState{failedAttempts: 2, createdAt: fresh}

	partly := correlationKey{"alice", "10.0.0.1"}
	shielded := correlationKey{"bob", "10.0.0.2"} // a fresh head keeps a stale entry behind it
	gone := correlationKey{"carol", "10.0.0.3"}

	c.accepts[partly] = []acceptEntry{
		{timestamp: ts(1), createdAt: stale},
		{timestamp: ts(2), createdAt: stale},
		{timestamp: ts(3), createdAt: fresh},
	}
	c.accepts[shielded] = []acceptEntry{
		{timestamp: ts(4), createdAt: fresh},
		{timestamp: ts(5), createdAt: stale},
	}
	c.accepts[gone] = []acceptEntry{{timestamp: ts(6), createdAt: stale}}

	// Pending sessions age by their login time.
	c.pendingSessions[partly] = []pendingSessionEntry{{loginTime: stale}, {loginTime: fresh}}
	c.pendingSessions[shielded] = []pendingSessionEntry{{loginTime: fresh}, {loginTime: stale}}
	c.pendingSessions[gone] = []pendingSessionEntry{{loginTime: stale}}

	c.Cleanup()

	if len(c.pids) != 1 || c.pids[2] == nil {
		t.Errorf("expected only PID 2 to survive, got %+v", c.pids)
	}
	wantAccepts := map[correlationKey][]acceptEntry{
		partly:   {{timestamp: ts(3), createdAt: fresh}},
		shielded: {{timestamp: ts(4), createdAt: fresh}, {timestamp: ts(5), createdAt: stale}},
	}
	if !reflect.DeepEqual(c.accepts, wantAccepts) {
		t.Errorf("accepts = %+v, want %+v", c.accepts, wantAccepts)
	}
	wantPending := map[correlationKey][]pendingSessionEntry{
		partly:   {{loginTime: fresh}},
		shielded: {{loginTime: fresh}, {loginTime: stale}},
	}
	if !reflect.DeepEqual(c.pendingSessions, wantPending) {
		t.Errorf("pendingSessions = %+v, want %+v", c.pendingSessions, wantPending)
	}
}

func TestCorrelator_MatchOrParkSession(t *testing.T) {
	c := newSessionCorrelator(5 * time.Minute)
	acceptTime := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	loginTime := acceptTime.Add(2 * time.Second)

	// Accept first: the session takes it and nothing stays queued.
	c.RecordAccept(1001, "alice", "192.168.1.10", acceptTime)
	got, ok := c.MatchOrParkSession("alice", "192.168.1.10", loginTime)
	if !ok || !got.Equal(acceptTime) {
		t.Errorf("MatchOrParkSession = %v, %v; want %v, true", got, ok, acceptTime)
	}
	if len(c.accepts) != 0 || len(c.pendingSessions) != 0 {
		t.Fatalf("queues not empty: accepts %+v, pending %+v", c.accepts, c.pendingSessions)
	}

	// Session first: it is parked and the next accept resolves it.
	if _, ok := c.MatchOrParkSession("alice", "192.168.1.10", loginTime); ok {
		t.Fatal("MatchOrParkSession matched without a recorded accept")
	}
	_, setup := c.RecordAccept(1002, "alice", "192.168.1.10", acceptTime)
	if setup == nil || setup.User != "alice" || setup.Duration != 2*time.Second {
		t.Errorf("setup = %+v, want alice 2s", setup)
	}
	if len(c.accepts) != 0 || len(c.pendingSessions) != 0 {
		t.Errorf("queues not empty: accepts %+v, pending %+v", c.accepts, c.pendingSessions)
	}
}

// checkNotBothQueued fails if a key has both an accept and a pending session
// queued (they should have matched each other), or keeps an empty queue.
func checkNotBothQueued(t *testing.T, c *sessionCorrelator) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, q := range c.accepts {
		if len(q) == 0 {
			t.Errorf("%v: empty accept queue left in the map", key)
		}
		if n := len(c.pendingSessions[key]); n > 0 {
			t.Errorf("%v: %d accepts and %d pending sessions queued together", key, len(q), n)
		}
	}
	for key, q := range c.pendingSessions {
		if len(q) == 0 {
			t.Errorf("%v: empty pending session queue left in the map", key)
		}
	}
}

// TestCorrelator_RandomSequencesNeverQueueBothSides drives random sequences
// of RecordAccept and MatchOrParkSession over a few keys and checks the
// results against a FIFO model, and the invariant after every call.
func TestCorrelator_RandomSequencesNeverQueueBothSides(t *testing.T) {
	keys := []correlationKey{{"alice", "10.0.0.1"}, {"alice", "10.0.0.2"}, {"bob", "10.0.0.1"}}
	base := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	for seed := range uint64(50) {
		rng := rand.New(rand.NewPCG(seed, 0))
		c := newSessionCorrelator(5 * time.Minute)
		// Per key, at most one of the two model queues is non-empty.
		modelAccepts := map[correlationKey][]time.Time{}
		modelSessions := map[correlationKey][]time.Time{}
		for step := range 200 {
			key := keys[rng.IntN(len(keys))]
			// Random times, so that some accepts come after their session.
			ts := base.Add(time.Duration(rng.IntN(20)) * time.Second)
			if rng.IntN(2) == 0 {
				_, setup := c.RecordAccept(int32(step), key.user, key.remoteIP, ts)
				var want *SetupResult
				if q := modelSessions[key]; len(q) > 0 {
					if d := q[0].Sub(ts); d >= 0 {
						want = &SetupResult{User: key.user, Duration: d}
					}
					modelSessions[key] = q[1:]
				} else {
					modelAccepts[key] = append(modelAccepts[key], ts)
				}
				if !reflect.DeepEqual(setup, want) {
					t.Fatalf("seed %d step %d: RecordAccept(%v, %v) setup = %+v, want %+v", seed, step, key, ts, setup, want)
				}
			} else {
				got, ok := c.MatchOrParkSession(key.user, key.remoteIP, ts)
				var want time.Time
				wantOK := len(modelAccepts[key]) > 0
				if wantOK {
					want = modelAccepts[key][0]
					modelAccepts[key] = modelAccepts[key][1:]
				} else {
					modelSessions[key] = append(modelSessions[key], ts)
				}
				if ok != wantOK || !got.Equal(want) {
					t.Fatalf("seed %d step %d: MatchOrParkSession(%v, %v) = %v, %v; want %v, %v", seed, step, key, ts, got, ok, want, wantOK)
				}
			}
			checkNotBothQueued(t, c)
			if t.Failed() {
				t.Fatalf("seed %d step %d: invariant broken", seed, step)
			}
		}
	}
}

// TestCorrelator_ConcurrentAcceptsAndSessions runs auth log accepts and utmp
// sessions for the same keys concurrently, as Run and Collect do. With as
// many accepts as sessions per key, every one of them must find its match.
func TestCorrelator_ConcurrentAcceptsAndSessions(t *testing.T) {
	const keys, perKey = 64, 500
	c := newSessionCorrelator(5 * time.Minute)
	acceptTime := time.Now()
	loginTime := acceptTime.Add(time.Second) // never a negative duration

	var matched atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for k := range keys {
		user, ip := fmt.Sprintf("user%d", k), "10.0.0.1"
		wg.Go(func() {
			<-start
			for i := range perKey {
				if _, setup := c.RecordAccept(int32(k*perKey+i), user, ip, acceptTime); setup != nil {
					matched.Add(1)
				}
			}
		})
		wg.Go(func() {
			<-start
			for range perKey {
				if _, ok := c.MatchOrParkSession(user, ip, loginTime); ok {
					matched.Add(1)
				}
			}
		})
	}
	close(start)
	wg.Wait()

	checkNotBothQueued(t, c)
	if got := matched.Load(); got != keys*perKey {
		t.Errorf("matched %d accept/session pairs, want %d", got, keys*perKey)
	}
	if len(c.accepts) != 0 || len(c.pendingSessions) != 0 {
		t.Errorf("unmatched entries left: %d accept keys, %d pending session keys", len(c.accepts), len(c.pendingSessions))
	}
}
