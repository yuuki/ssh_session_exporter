//go:build linux

package main

import (
	"context"
	"testing"
	"time"

	"github.com/yuuki/ssh_session_exporter/authlog"
)

func TestResolveAuthLogPath_DefaultPathExists(t *testing.T) {
	path, ok := resolveAuthLogPath(defaultAuthLogPath, false, defaultAuthLogCandidates, func(path string) bool {
		return path == defaultAuthLogPath
	})
	if !ok {
		t.Fatal("expected auth log path to be resolved")
	}
	if path != defaultAuthLogPath {
		t.Fatalf("expected default path %q, got %q", defaultAuthLogPath, path)
	}
}

func TestResolveAuthLogPath_FallsBackToSecure(t *testing.T) {
	path, ok := resolveAuthLogPath(defaultAuthLogPath, false, defaultAuthLogCandidates, func(path string) bool {
		return path == "/var/log/secure"
	})
	if !ok {
		t.Fatal("expected auth log path to be resolved")
	}
	if path != "/var/log/secure" {
		t.Fatalf("expected fallback path, got %q", path)
	}
}

func TestResolveAuthLogPath_DisablesWatcherWhenNoDefaultPathExists(t *testing.T) {
	path, ok := resolveAuthLogPath(defaultAuthLogPath, false, defaultAuthLogCandidates, func(string) bool {
		return false
	})
	if ok {
		t.Fatal("expected auth log watcher to be disabled")
	}
	if path != "" {
		t.Fatalf("expected empty path, got %q", path)
	}
}

func TestResolveAuthLogPath_UsesExplicitPathAsIs(t *testing.T) {
	const customPath = "/custom/auth.log"

	path, ok := resolveAuthLogPath(customPath, true, defaultAuthLogCandidates, func(string) bool {
		return false
	})
	if !ok {
		t.Fatal("expected explicit auth log path to remain enabled")
	}
	if path != customPath {
		t.Fatalf("expected explicit path %q, got %q", customPath, path)
	}
}

func TestFanOutAuthEvents_ForwardsAndClosesWhenSourceCloses(t *testing.T) {
	src := make(chan authlog.AuthEvent, 2)
	out := make(chan authlog.AuthEvent, 2)
	src <- authlog.AuthEvent{Type: authlog.EventInvalidUser, User: "admin"}
	src <- authlog.AuthEvent{Type: authlog.EventAuthSuccess, User: "alice"}
	close(src)

	fanOutAuthEvents(context.Background(), src, out, nil)

	var users []string
	for e := range out { // fanOutAuthEvents closed out, or this would block
		users = append(users, e.User)
	}
	if len(users) != 2 || users[0] != "admin" || users[1] != "alice" {
		t.Fatalf("forwarded %v, want [admin alice] in order", users)
	}
}

func TestFanOutAuthEvents_ReturnsOnCancelWhileConsumerIsStuck(t *testing.T) {
	src := make(chan authlog.AuthEvent, 1)
	src <- authlog.AuthEvent{Type: authlog.EventAuthFailure, User: "alice"}
	out := make(chan authlog.AuthEvent) // nobody receives
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		fanOutAuthEvents(ctx, src, out, nil)
	}()
	time.Sleep(50 * time.Millisecond) // let it block on the send
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fanOutAuthEvents did not return after cancel")
	}
	if _, ok := <-out; ok {
		t.Fatal("expected the collector channel to be closed")
	}
}
