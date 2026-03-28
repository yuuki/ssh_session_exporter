# Login Setup: User+IP FIFO Correlation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace PID-based correlation with `{user, remoteIP}` FIFO queue correlation so `ssh_login_setup_seconds` works on modern OpenSSH (privsep always enabled, auth.log PID != utmp PID).

**Architecture:** Split correlator internals into two independent structures: (1) PID-keyed map for failure counting (`ssh_auth_attempts_before_success` — auth.log internal, works as-is), (2) `{user, remoteIP}`-keyed FIFO queues for login setup timing (`ssh_login_setup_seconds` — cross auth.log/utmp). Both coexist in one `sessionCorrelator` struct.

**Tech Stack:** Go, Prometheus client_golang, testutil

---

## Design

### New correlator internals

```go
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

type sessionCorrelator struct {
    mu              sync.Mutex
    pids            map[int32]*pidState                      // auth.log PID -> failure count
    accepts         map[correlationKey][]acceptEntry          // {user,ip} -> FIFO of accept times
    pendingSessions map[correlationKey][]pendingSessionEntry  // {user,ip} -> FIFO of parked sessions
    ttl             time.Duration
}
```

### API changes

| Old (pidCorrelator)                                  | New (sessionCorrelator)                                                   |
|------------------------------------------------------|---------------------------------------------------------------------------|
| `RecordFailure(pid)`                                 | `RecordFailure(pid)` (unchanged)                                          |
| `RecordAccept(pid, acceptTime) -> (failCount, setup)` | `RecordAccept(pid, user, remoteIP, acceptTime) -> (failCount, setup)`     |
| `ConsumeAccept(pid) -> (time, bool)`                 | `ConsumeAccept(user, remoteIP) -> (time, bool)`                           |
| `RecordNewSession(pid, user, loginTime)`             | `RecordNewSession(user, remoteIP, loginTime)`                             |
| `Cleanup()`                                          | `Cleanup()` (updated to trim FIFO queues)                                 |

### Collector call-site changes

**`Collect()` — new session detected:**
```go
// Before:
if acceptTime, ok := c.correlator.ConsumeAccept(newS.PID); ok { ... }
c.correlator.RecordNewSession(newS.PID, newS.User, newS.LoginTime)

// After:
if acceptTime, ok := c.correlator.ConsumeAccept(newS.User, newS.Host); ok { ... }
c.correlator.RecordNewSession(newS.User, newS.Host, newS.LoginTime)
```

**`Run()` — auth success event:**
```go
// Before:
failCount, setup := c.correlator.RecordAccept(event.PID, event.Timestamp)

// After:
failCount, setup := c.correlator.RecordAccept(event.PID, event.User, event.RemoteIP, event.Timestamp)
```

---

## Tasks

### Task 1: Rewrite correlator tests for {user, remoteIP} API

**Files:**
- Modify: `collector/correlator_test.go`

**Step 1: Rewrite all correlator tests**

Replace all `pidCorrelator` references with `sessionCorrelator`, and change login-setup-related tests to use `{user, remoteIP}` instead of PID. Keep `RecordFailure` test using PID.

```go
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
```

**Step 2: Run tests to verify they fail**

Run: `GOOS=linux go test ./collector/ -run TestCorrelator -v`
Expected: FAIL — `newSessionCorrelator` undefined

**Step 3: Commit test changes**

```bash
git add collector/correlator_test.go
git commit -m "test(correlator): rewrite tests for {user, remoteIP} FIFO correlation"
```

---

### Task 2: Implement new sessionCorrelator

**Files:**
- Modify: `collector/correlator.go`

**Step 1: Rewrite correlator.go**

```go
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
```

**Step 2: Run correlator tests**

Run: `GOOS=linux go test ./collector/ -run TestCorrelator -v`
Expected: All PASS

**Step 3: Commit**

```bash
git add collector/correlator.go
git commit -m "refactor(correlator): replace PID-based correlation with {user, remoteIP} FIFO queues

Modern OpenSSH (7.5+, privsep always enabled) uses different PIDs
for auth.log (pre-auth child or monitor) and utmp (post-auth child
or login shell). This made PID-based correlation always miss,
so ssh_login_setup_seconds was never observed.

PID-based failure counting (ssh_auth_attempts_before_success) is
kept as-is since it operates purely within auth.log."
```

---

### Task 3: Update collector tests for new API

**Files:**
- Modify: `collector/collector_test.go`

**Step 1: Update TestCollect_LoginSetupSeconds**

Change from PID-based `RecordAccept(pid, time)` to `RecordAccept(pid, user, remoteIP, time)`:

```go
func TestCollect_LoginSetupSeconds(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Now()
	acceptTime := now.Add(-2 * time.Second)

	reader := &mockReader{sessions: nil}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Simulate: auth success event recorded (PID differs from utmp PID).
	c.correlator.RecordAccept(5555, "alice", "192.168.1.10", acceptTime)

	// New session appears in utmp with a DIFFERENT PID (real-world scenario).
	reader.sessions = []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now, PID: 8001},
	}

	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	expected := `
# HELP ssh_login_setup_seconds Time from authentication success to session appearing in utmp.
# TYPE ssh_login_setup_seconds histogram
ssh_login_setup_seconds_bucket{user="alice",le="0.1"} 0
ssh_login_setup_seconds_bucket{user="alice",le="0.5"} 0
ssh_login_setup_seconds_bucket{user="alice",le="1"} 0
ssh_login_setup_seconds_bucket{user="alice",le="2"} 1
ssh_login_setup_seconds_bucket{user="alice",le="5"} 1
ssh_login_setup_seconds_bucket{user="alice",le="10"} 1
ssh_login_setup_seconds_bucket{user="alice",le="30"} 1
ssh_login_setup_seconds_bucket{user="alice",le="+Inf"} 1
ssh_login_setup_seconds_sum{user="alice"} 2
ssh_login_setup_seconds_count{user="alice"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_login_setup_seconds"); err != nil {
		t.Errorf("unexpected metrics:\n%v", err)
	}
}
```

**Step 2: Update TestCollect_LoginSetupSessionFirst**

Change the accept event to use a different PID from the utmp session:

```go
func TestCollect_LoginSetupSessionFirst(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Now()
	acceptTime := now.Add(-2 * time.Second)

	reader := &mockReader{sessions: nil}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Session appears in utmp BEFORE accept arrives.
	reader.sessions = []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now, PID: 9001},
	}
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	// Now accept arrives via Run() with a DIFFERENT PID.
	events := make(chan authlog.AuthEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Run(ctx, events)

	events <- authlog.AuthEvent{
		Type:      authlog.EventAuthSuccess,
		PID:       5555, // different PID from utmp
		User:      "alice",
		RemoteIP:  "192.168.1.10",
		Method:    "publickey",
		Timestamp: acceptTime,
	}

	time.Sleep(50 * time.Millisecond)

	expected := `
# HELP ssh_login_setup_seconds Time from authentication success to session appearing in utmp.
# TYPE ssh_login_setup_seconds histogram
ssh_login_setup_seconds_bucket{user="alice",le="0.1"} 0
ssh_login_setup_seconds_bucket{user="alice",le="0.5"} 0
ssh_login_setup_seconds_bucket{user="alice",le="1"} 0
ssh_login_setup_seconds_bucket{user="alice",le="2"} 1
ssh_login_setup_seconds_bucket{user="alice",le="5"} 1
ssh_login_setup_seconds_bucket{user="alice",le="10"} 1
ssh_login_setup_seconds_bucket{user="alice",le="30"} 1
ssh_login_setup_seconds_bucket{user="alice",le="+Inf"} 1
ssh_login_setup_seconds_sum{user="alice"} 2
ssh_login_setup_seconds_count{user="alice"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_login_setup_seconds"); err != nil {
		t.Errorf("unexpected metrics (session-before-accept path):\n%v", err)
	}
}
```

**Step 3: Update TestRun_AuthAttemptsBeforeSuccess**

Add user and remoteIP params to match new `RecordAccept` signature (PID still used for failure counting):

The existing test should still work since the `Run()` method calls `RecordAccept` internally. No changes needed to this test — only the `Run()` implementation needs updating (Task 4).

**Step 4: Run tests to verify they fail (collector.go not yet updated)**

Run: `GOOS=linux go test ./collector/ -run "TestCollect_LoginSetup" -v`
Expected: FAIL — `RecordAccept` signature mismatch / `ConsumeAccept` argument count

**Step 5: Commit test changes**

```bash
git add collector/collector_test.go
git commit -m "test(collector): update login setup tests for user+IP correlation

Tests now use different PIDs for auth.log events and utmp sessions,
matching real-world OpenSSH privsep behavior."
```

---

### Task 4: Update collector.go to use new correlator API

**Files:**
- Modify: `collector/collector.go`

**Step 1: Update collector field type and constructor**

In `SSHCollector` struct, change field type:
```go
// Old:
correlator         *pidCorrelator
// New:
correlator         *sessionCorrelator
```

In `New()`:
```go
// Old:
correlator: newPIDCorrelator(correlatorTTL),
// New:
correlator: newSessionCorrelator(correlatorTTL),
```

**Step 2: Update `Collect()` method**

Change the new-session loop (lines 167-178):
```go
for _, newS := range delta.NewSessions {
    c.connections.WithLabelValues(newS.User, newS.Host).Inc()
    if acceptTime, ok := c.correlator.ConsumeAccept(newS.User, newS.Host); ok {
        setupDuration := newS.LoginTime.Sub(acceptTime)
        if setupDuration >= 0 {
            c.loginSetup.WithLabelValues(newS.User).Observe(setupDuration.Seconds())
        }
    } else {
        c.correlator.RecordNewSession(newS.User, newS.Host, newS.LoginTime)
    }
}
```

**Step 3: Update `Run()` method**

Change the `EventAuthSuccess` case (line 221):
```go
case authlog.EventAuthSuccess:
    c.authSuccesses.WithLabelValues(event.User, event.RemoteIP, event.Method).Inc()
    failCount, setup := c.correlator.RecordAccept(event.PID, event.User, event.RemoteIP, event.Timestamp)
    c.authAttempts.WithLabelValues(event.User).Observe(float64(failCount))
    if setup != nil {
        c.loginSetup.WithLabelValues(setup.User).Observe(setup.Duration.Seconds())
    }
```

**Step 4: Run all collector tests**

Run: `GOOS=linux go test ./collector/ -v`
Expected: All PASS

**Step 5: Run full test suite**

Run: `GOOS=linux go vet ./... && go test ./...`
Expected: All PASS (utmp tests skipped on macOS as expected)

**Step 6: Verify compilation**

Run: `GOOS=linux go build -o /dev/null .`
Expected: Success

**Step 7: Commit**

```bash
git add collector/collector.go
git commit -m "fix(collector): use {user, remoteIP} correlation for login setup timing

ConsumeAccept and RecordNewSession now match on {user, remoteIP}
instead of PID, fixing ssh_login_setup_seconds on OpenSSH 7.5+
where privsep causes auth.log PID != utmp PID."
```

---

### Task 5: Update e2e tests for different PIDs

**Files:**
- Modify: `e2e/e2e_test.go`

**Step 1: Update LoginSetup_AcceptFirst**

Change the utmp PID to differ from the auth.log PID (line 461):
```go
t.Run("LoginSetup_AcceptFirst", func(t *testing.T) {
    // Accept log line arrives first (sshd PID 7001).
    appendAuthLog(t, fmt.Sprintf("Mar 27 12:06:00 server sshd[7001]: Accepted publickey for dave from 10.0.0.70 port 22 ssh2"))

    time.Sleep(500 * time.Millisecond)

    // Session appears in utmp with DIFFERENT PID (login shell PID).
    writeUtmpRecords(t, []sessionSpec{
        {User: "dave", TTY: "pts/5", Host: "10.0.0.70", PID: 7099, TvSec: now + 2},
    })
    // ... rest unchanged
})
```

**Step 2: Update LoginSetup_SessionFirst**

Change the auth.log PID to differ from the utmp PID (line 490):
```go
t.Run("LoginSetup_SessionFirst", func(t *testing.T) {
    clearUtmp(t)
    triggerAndScrape(t)

    // Session appears with utmp PID 8001.
    writeUtmpRecords(t, []sessionSpec{
        {User: "eve", TTY: "pts/6", Host: "10.0.0.80", PID: 8001, TvSec: now + 4},
    })

    triggerAndScrape(t)

    // Accept arrives with DIFFERENT sshd PID 8099.
    appendAuthLog(t, "Mar 27 12:07:00 server sshd[8099]: Accepted publickey for eve from 10.0.0.80 port 22 ssh2")
    // ... rest unchanged
})
```

**Step 3: Commit**

```bash
git add e2e/e2e_test.go
git commit -m "test(e2e): use different PIDs for auth.log and utmp in login setup tests

Reflects real-world OpenSSH privsep behavior where sshd auth PID
differs from utmp session PID."
```

---

### Task 6: Update CLAUDE.md architecture docs

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Update correlator description in Architecture section**

Replace the `pidCorrelator` reference:

Old text (in **collector** description):
> A `pidCorrelator` (`correlator.go`) tracks per-PID state (failure count, accept timestamp) to compute `ssh_login_setup_seconds` and `ssh_auth_attempts_before_success`.

New text:
> A `sessionCorrelator` (`correlator.go`) handles two concerns: (1) PID-based failure counting for `ssh_auth_attempts_before_success` (auth.log internal), and (2) `{user, remoteIP}` FIFO queue matching for `ssh_login_setup_seconds` (cross auth.log/utmp — PID-independent because OpenSSH privsep uses different PIDs for auth and session processes).

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update correlator architecture description"
```
