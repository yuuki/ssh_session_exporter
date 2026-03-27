package authlog

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileWatcher_ParsesNewLines(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "auth.log")

	// Create the file first so MustExist succeeds.
	f, err := os.Create(logFile)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	f.Close()

	w := NewFileWatcher(logFile, slog.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := w.Start(ctx); err != nil {
		t.Fatalf("start watcher: %v", err)
	}
	defer w.Stop()

	// Write lines to the file.
	f, err = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	_, err = f.WriteString("Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 192.168.1.10 port 22 ssh2\n")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err = f.WriteString("Jan  1 12:00:01 server sshd[1234]: Accepted publickey for bob from 10.0.0.5 port 22 ssh2\n")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	// Read events.
	var events []AuthEvent
	timeout := time.After(3 * time.Second)
	for len(events) < 2 {
		select {
		case e := <-w.Events():
			events = append(events, e)
		case <-timeout:
			t.Fatalf("timeout waiting for events, got %d", len(events))
		}
	}

	if events[0].Type != EventAuthFailure || events[0].User != "alice" {
		t.Errorf("unexpected event[0]: %+v", events[0])
	}
	if events[1].Type != EventAuthSuccess || events[1].User != "bob" {
		t.Errorf("unexpected event[1]: %+v", events[1])
	}
}

func TestFileWatcher_SkipsNonSSHLines(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "auth.log")

	f, err := os.Create(logFile)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	f.Close()

	w := NewFileWatcher(logFile, slog.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := w.Start(ctx); err != nil {
		t.Fatalf("start watcher: %v", err)
	}
	defer w.Stop()

	f, err = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	// Non-SSH line followed by SSH line.
	_, _ = f.WriteString("Jan  1 12:00:00 server systemd[1]: Started something\n")
	_, _ = f.WriteString("Jan  1 12:00:01 server sshd[1234]: Accepted password for root from 10.0.0.1 port 22 ssh2\n")
	f.Close()

	select {
	case e := <-w.Events():
		if e.Type != EventAuthSuccess || e.User != "root" {
			t.Errorf("unexpected event: %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}
