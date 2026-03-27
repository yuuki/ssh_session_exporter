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
	"github.com/yuuki/ssh_sesshon_exporter/authlog"
	"github.com/yuuki/ssh_sesshon_exporter/sessiontracker"
	"github.com/yuuki/ssh_sesshon_exporter/utmp"
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

func TestCollect_ConnectionCounters(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Now()
	reader := &mockReader{
		sessions: []utmp.Session{
			{User: "alice", TTY: "pts/0", Host: "192.168.1.10", LoginTime: now},
		},
	}
	tracker := sessiontracker.New(slog.Default())

	c, err := New(reg, reader, tracker, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Trigger a collect to detect session changes and update counters.
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	// Now verify the counter via the registry.
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
