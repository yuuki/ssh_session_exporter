package collector

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/yuuki/ssh_session_exporter/authlog"
	"github.com/yuuki/ssh_session_exporter/sessiontracker"
	"github.com/yuuki/ssh_session_exporter/utmp"
)

type mockReader struct {
	sessions []utmp.Session
	err      error
}

func (m *mockReader) ReadSessions() ([]utmp.Session, error) {
	return m.sessions, m.err
}

func TestCollect_ActiveSessions(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reader := &mockReader{
		sessions: []utmp.Session{
			{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: time.Now()},
			{User: "bob", TTY: "pts/1", Host: "10.0.0.5", LoginTime: time.Now()},
		},
	}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	expected := `
# HELP ssh_sessions_active Number of currently active SSH sessions.
# TYPE ssh_sessions_active gauge
ssh_sessions_active{remote_ip="192.168.1.10",tty="pts/0",user="alice"} 1
ssh_sessions_active{remote_ip="10.0.0.5",tty="pts/1",user="bob"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), "ssh_sessions_active"); err != nil {
		t.Errorf("unexpected metrics:\n%v", err)
	}
}

func TestCollect_ScrapeSuccess(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reader := &mockReader{sessions: nil}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	expected := `
# HELP ssh_exporter_scrape_success Whether the SSH exporter scrape was successful.
# TYPE ssh_exporter_scrape_success gauge
ssh_exporter_scrape_success 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), "ssh_exporter_scrape_success"); err != nil {
		t.Errorf("unexpected metrics:\n%v", err)
	}
}

func TestCollect_ScrapeFailure(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reader := &mockReader{err: errors.New("test error")}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	expected := `
# HELP ssh_exporter_scrape_success Whether the SSH exporter scrape was successful.
# TYPE ssh_exporter_scrape_success gauge
ssh_exporter_scrape_success 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), "ssh_exporter_scrape_success"); err != nil {
		t.Errorf("unexpected metrics:\n%v", err)
	}
}

func TestCollect_BaselineNotCounted(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Now()
	baselineSessions := []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now},
	}
	reader := &mockReader{sessions: baselineSessions}
	tracker := sessiontracker.New(slog.Default())
	tracker.Initialize(baselineSessions)

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// First scrape: baseline session still present — no connection or disconnection events.
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	expected := `
# HELP ssh_connections_total Total number of SSH connections established.
# TYPE ssh_connections_total counter
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_connections_total"); err != nil {
		t.Errorf("baseline sessions should not be counted as new connections:\n%v", err)
	}

	// Baseline session disappears on second scrape.
	// The disconnection IS counted because the session ended while the exporter
	// was running — only the initial connection event is suppressed.
	reader.sessions = nil
	ch = make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	disconnExpected := `
# HELP ssh_disconnections_total Total number of SSH disconnections.
# TYPE ssh_disconnections_total counter
ssh_disconnections_total{remote_ip="192.168.1.10",user="alice"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(disconnExpected), "ssh_disconnections_total"); err != nil {
		t.Errorf("disconnection of baseline session should be counted:\n%v", err)
	}
}

func TestCollect_ConnectionCounters(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Now()
	// Start with no sessions for baseline.
	reader := &mockReader{sessions: nil}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A new session appears after baseline.
	reader.sessions = []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now},
	}

	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	expected := `
# HELP ssh_connections_total Total number of SSH connections established.
# TYPE ssh_connections_total counter
ssh_connections_total{remote_ip="192.168.1.10",user="alice"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_connections_total"); err != nil {
		t.Errorf("unexpected metrics after first scrape:\n%v", err)
	}
}

func TestRun_AuthFailures(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reader := &mockReader{sessions: nil}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	events := make(chan authlog.AuthEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Run(ctx, events)

	events <- authlog.AuthEvent{
		Type:     authlog.EventAuthFailure,
		User:     "admin",
		RemoteIP: "10.0.0.99",
		Method:   "password",
	}
	events <- authlog.AuthEvent{
		Type:     authlog.EventAuthFailure,
		User:     "admin",
		RemoteIP: "10.0.0.99",
		Method:   "password",
	}

	// Give the goroutine time to process.
	time.Sleep(50 * time.Millisecond)

	expected := `
# HELP ssh_auth_failures_total Total number of SSH authentication failures.
# TYPE ssh_auth_failures_total counter
ssh_auth_failures_total{method="password",remote_ip="10.0.0.99",user="admin"} 2
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_auth_failures_total"); err != nil {
		t.Errorf("unexpected metrics:\n%v", err)
	}
}

func TestRun_AuthSuccess(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reader := &mockReader{sessions: nil}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	events := make(chan authlog.AuthEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Run(ctx, events)

	events <- authlog.AuthEvent{
		Type:     authlog.EventAuthSuccess,
		User:     "alice",
		RemoteIP: "192.168.1.10",
		Method:   "publickey",
	}

	time.Sleep(50 * time.Millisecond)

	expected := `
# HELP ssh_auth_success_total Total number of successful SSH authentications.
# TYPE ssh_auth_success_total counter
ssh_auth_success_total{method="publickey",remote_ip="192.168.1.10",user="alice"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_auth_success_total"); err != nil {
		t.Errorf("unexpected metrics:\n%v", err)
	}
}

func TestRun_InvalidUser(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reader := &mockReader{sessions: nil}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	events := make(chan authlog.AuthEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Run(ctx, events)

	events <- authlog.AuthEvent{
		Type:     authlog.EventInvalidUser,
		User:     "hacker",
		RemoteIP: "10.0.0.99",
	}
	events <- authlog.AuthEvent{
		Type:     authlog.EventInvalidUser,
		User:     "hacker",
		RemoteIP: "10.0.0.99",
	}

	time.Sleep(50 * time.Millisecond)

	expected := `
# HELP ssh_invalid_user_attempts_total Total number of SSH authentication attempts for invalid users.
# TYPE ssh_invalid_user_attempts_total counter
ssh_invalid_user_attempts_total{remote_ip="10.0.0.99",user="hacker"} 2
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_invalid_user_attempts_total"); err != nil {
		t.Errorf("unexpected metrics:\n%v", err)
	}
}

func TestRun_PreauthDisconnect(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reader := &mockReader{sessions: nil}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	events := make(chan authlog.AuthEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Run(ctx, events)

	events <- authlog.AuthEvent{
		Type:     authlog.EventPreauthDisconnect,
		User:     "root",
		RemoteIP: "10.0.0.1",
	}

	time.Sleep(50 * time.Millisecond)

	expected := `
# HELP ssh_preauth_disconnects_total Total number of SSH disconnections before authentication completed.
# TYPE ssh_preauth_disconnects_total counter
ssh_preauth_disconnects_total{remote_ip="10.0.0.1",user="root"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_preauth_disconnects_total"); err != nil {
		t.Errorf("unexpected metrics:\n%v", err)
	}
}

func TestRun_AuthAttemptsBeforeSuccess(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reader := &mockReader{sessions: nil}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	events := make(chan authlog.AuthEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Run(ctx, events)

	// Two failures followed by a success for the same PID.
	events <- authlog.AuthEvent{
		Type: authlog.EventAuthFailure, PID: 7001,
		User: "alice", RemoteIP: "192.168.1.10", Method: "password",
	}
	events <- authlog.AuthEvent{
		Type: authlog.EventAuthFailure, PID: 7001,
		User: "alice", RemoteIP: "192.168.1.10", Method: "password",
	}
	events <- authlog.AuthEvent{
		Type: authlog.EventAuthSuccess, PID: 7001,
		User: "alice", RemoteIP: "192.168.1.10", Method: "password",
		Timestamp: time.Now(),
	}

	time.Sleep(50 * time.Millisecond)

	expected := `
# HELP ssh_auth_attempts_before_success Number of failed authentication attempts before a successful login.
# TYPE ssh_auth_attempts_before_success histogram
ssh_auth_attempts_before_success_bucket{user="alice",le="0"} 0
ssh_auth_attempts_before_success_bucket{user="alice",le="1"} 0
ssh_auth_attempts_before_success_bucket{user="alice",le="2"} 1
ssh_auth_attempts_before_success_bucket{user="alice",le="3"} 1
ssh_auth_attempts_before_success_bucket{user="alice",le="5"} 1
ssh_auth_attempts_before_success_bucket{user="alice",le="10"} 1
ssh_auth_attempts_before_success_bucket{user="alice",le="+Inf"} 1
ssh_auth_attempts_before_success_sum{user="alice"} 2
ssh_auth_attempts_before_success_count{user="alice"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_auth_attempts_before_success"); err != nil {
		t.Errorf("unexpected metrics:\n%v", err)
	}
}

func TestCollect_LoginSetupSeconds(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Now()
	acceptTime := now.Add(-2 * time.Second) // auth accepted 2 seconds ago

	reader := &mockReader{sessions: nil}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Simulate: auth success event was recorded with PID 8001.
	c.correlator.RecordAccept(8001, acceptTime)

	// New session appears in utmp with same PID.
	reader.sessions = []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now, PID: 8001},
	}

	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	// The login setup duration should be approximately 2 seconds.
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

	// At this point the session is parked in pendingSessions.
	// Now accept arrives via Run().
	events := make(chan authlog.AuthEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Run(ctx, events)

	events <- authlog.AuthEvent{
		Type:      authlog.EventAuthSuccess,
		PID:       9001,
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

func TestCollect_ShortSessions(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Now()
	// Session started 10 seconds ago (well within 30s threshold).
	sessions := []utmp.Session{
		{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now.Add(-10 * time.Second)},
	}
	reader := &mockReader{sessions: sessions}
	tracker := sessiontracker.New(slog.Default())
	tracker.Initialize(sessions)

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// First scrape: session is active.
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	// Session ends.
	reader.sessions = nil
	ch = make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	expected := `
# HELP ssh_short_sessions_total Total number of SSH sessions that ended within 30 seconds.
# TYPE ssh_short_sessions_total counter
ssh_short_sessions_total{remote_ip="192.168.1.10",user="alice"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_short_sessions_total"); err != nil {
		t.Errorf("unexpected metrics:\n%v", err)
	}
}

func TestCollect_LongSessionNotShort(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Now()
	// Session started 5 minutes ago (well beyond 30s threshold).
	sessions := []utmp.Session{
		{User: "bob", TTY: "pts/1", Host: "10.0.0.5", LoginTime: now.Add(-5 * time.Minute)},
	}
	reader := &mockReader{sessions: sessions}
	tracker := sessiontracker.New(slog.Default())
	tracker.Initialize(sessions)

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// First scrape: session is active.
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	// Session ends.
	reader.sessions = nil
	ch = make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	// ssh_short_sessions_total should have no entries for bob.
	expected := `
# HELP ssh_short_sessions_total Total number of SSH sessions that ended within 30 seconds.
# TYPE ssh_short_sessions_total counter
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "ssh_short_sessions_total"); err != nil {
		t.Errorf("long session was incorrectly counted as short:\n%v", err)
	}
}
