package collector

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuuki/ssh_session_exporter/authlog"
	"github.com/yuuki/ssh_session_exporter/sessiontracker"
)

func newLifecycleCollector(t *testing.T) *SSHCollector {
	t.Helper()
	c, err := New(prometheus.NewPedanticRegistry(), &mockReader{}, sessiontracker.New(slog.Default()), slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// waitReturn fails the test unless done is closed soon: main relies on the
// loops returning so that the process can shut down.
func waitReturn(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

func TestRun_ReturnsWhenContextIsCancelled(t *testing.T) {
	c := newLifecycleCollector(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx, make(chan authlog.AuthEvent)) // never sends nor closes
	}()
	cancel()
	waitReturn(t, done, "Run after cancel")
}

func TestRun_ReturnsWhenEventsChannelIsClosed(t *testing.T) {
	c := newLifecycleCollector(t)
	events := make(chan authlog.AuthEvent, 1)
	events <- authlog.AuthEvent{Type: authlog.EventInvalidUser, User: "admin", RemoteIP: "192.0.2.1"}
	close(events)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(context.Background(), events)
	}()
	waitReturn(t, done, "Run after the events channel closed")
}

func TestRunCleanup_ReturnsWhenContextIsCancelled(t *testing.T) {
	c := newLifecycleCollector(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.RunCleanup(ctx)
	}()
	cancel()
	waitReturn(t, done, "RunCleanup after cancel")
}
