package authlog

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileWatcher_ParsesNewLines(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "auth.log")

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

	f, err = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	_, err = f.WriteString("Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 192.168.1.10 port 22 ssh2\n")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err = f.WriteString("Jan  1 12:00:01 server sshd[1234]: Failed publickey for bob from 10.0.0.5 port 22 ssh2\n")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

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
	if events[1].Type != EventAuthFailure || events[1].User != "bob" {
		t.Errorf("unexpected event[1]: %+v", events[1])
	}
}

func TestFileWatcher_SkipsNonMatchingLines(t *testing.T) {
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
	// Non-matching line followed by a failure line.
	_, _ = f.WriteString("Jan  1 12:00:00 server systemd[1]: Started something\n")
	_, _ = f.WriteString("Jan  1 12:00:02 server sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2\n")
	f.Close()

	select {
	case e := <-w.Events():
		if e.Type != EventAuthFailure || e.User != "root" {
			t.Errorf("unexpected event: %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestFileWatcher_AllEventTypes(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "auth.log")

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

	f, err = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	_, _ = f.WriteString("Jan  1 12:00:00 server sshd[1001]: Failed password for alice from 192.168.1.10 port 22 ssh2\n")
	_, _ = f.WriteString("Jan  1 12:00:01 server sshd[1002]: Accepted publickey for bob from 10.0.0.5 port 22 ssh2\n")
	_, _ = f.WriteString("Jan  1 12:00:02 server sshd[1003]: Invalid user admin from 10.0.0.99 port 22\n")
	_, _ = f.WriteString("Jan  1 12:00:03 server sshd[1004]: Disconnected from authenticating user root 10.0.0.1 port 22 [preauth]\n")
	f.Close()

	expected := []struct {
		eventType EventType
		user      string
	}{
		{EventAuthFailure, "alice"},
		{EventAuthSuccess, "bob"},
		{EventInvalidUser, "admin"},
		{EventPreauthDisconnect, "root"},
	}

	timeout := time.After(3 * time.Second)
	for i, exp := range expected {
		select {
		case e := <-w.Events():
			if e.Type != exp.eventType {
				t.Errorf("event[%d]: Type = %d, want %d", i, e.Type, exp.eventType)
			}
			if e.User != exp.user {
				t.Errorf("event[%d]: User = %q, want %q", i, e.User, exp.user)
			}
		case <-timeout:
			t.Fatalf("timeout waiting for event[%d]", i)
		}
	}
}

// The rotation tests rely on the replacement file being smaller than what the
// watcher has already read, which is how it detects rotation.
const (
	rotationLongLine  = "Jan  1 12:00:00 server sshd[1001]: Failed password for alice from 192.168.1.10 port 22 ssh2\n"
	rotationShortLine = "Jan  1 12:00:05 server sshd[2002]: Failed password for bob from 10.0.0.5 port 22 ssh2\n"
)

// syncBuffer is a log sink that is safe to read while the watcher writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newEmptyLogFile(t *testing.T) string {
	t.Helper()
	logFile := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(logFile, nil, 0644); err != nil {
		t.Fatalf("create file: %v", err)
	}
	return logFile
}

func startTestWatcher(t *testing.T, logFile string, logger *slog.Logger) *FileWatcher {
	t.Helper()
	w := NewFileWatcher(logFile, logger)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	if err := w.Start(ctx); err != nil {
		t.Fatalf("start watcher: %v", err)
	}
	t.Cleanup(w.Stop)
	return w
}

func appendToFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func receiveEvent(t *testing.T, w *FileWatcher) AuthEvent {
	t.Helper()
	select {
	case e, ok := <-w.Events():
		if !ok {
			t.Fatal("events channel closed while waiting for an event")
		}
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for event")
	}
	return AuthEvent{}
}

// waitForPolls gives the watcher time for several ticks, so that what was
// written so far has been read before the test changes the file again.
func waitForPolls() {
	time.Sleep(300 * time.Millisecond)
}

func TestFileWatcher_JoinsLineSplitAcrossReads(t *testing.T) {
	logFile := newEmptyLogFile(t)
	w := startTestWatcher(t, logFile, slog.Default())

	appendToFile(t, logFile, "Jan  1 12:00:00 server sshd[1001]: Failed password for al")
	waitForPolls()
	appendToFile(t, logFile, "ice from 192.168.1.10 port 22 ssh2\n")

	e := receiveEvent(t, w)
	if e.Type != EventAuthFailure || e.User != "alice" || e.PID != 1001 {
		t.Errorf("unexpected event: %+v", e)
	}
}

func TestFileWatcher_FollowsCopyTruncateRotation(t *testing.T) {
	logFile := newEmptyLogFile(t)
	w := startTestWatcher(t, logFile, slog.Default())

	appendToFile(t, logFile, rotationLongLine)
	if e := receiveEvent(t, w); e.User != "alice" {
		t.Fatalf("unexpected first event: %+v", e)
	}

	if err := os.WriteFile(logFile, []byte(rotationShortLine), 0644); err != nil {
		t.Fatalf("truncate and rewrite: %v", err)
	}
	if e := receiveEvent(t, w); e.User != "bob" || e.PID != 2002 {
		t.Errorf("unexpected event after truncation: %+v", e)
	}
}

func TestFileWatcher_FollowsRenameRotation(t *testing.T) {
	logFile := newEmptyLogFile(t)
	w := startTestWatcher(t, logFile, slog.Default())

	appendToFile(t, logFile, rotationLongLine)
	if e := receiveEvent(t, w); e.User != "alice" {
		t.Fatalf("unexpected first event: %+v", e)
	}

	if err := os.Rename(logFile, logFile+".1"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.WriteFile(logFile, []byte(rotationShortLine), 0644); err != nil {
		t.Fatalf("create new log: %v", err)
	}
	if e := receiveEvent(t, w); e.User != "bob" || e.PID != 2002 {
		t.Errorf("unexpected event after rotation: %+v", e)
	}
}

func TestFileWatcher_KeepsPollingWhileFileIsMissing(t *testing.T) {
	logFile := newEmptyLogFile(t)
	w := startTestWatcher(t, logFile, slog.Default())

	appendToFile(t, logFile, rotationLongLine)
	if e := receiveEvent(t, w); e.User != "alice" {
		t.Fatalf("unexpected first event: %+v", e)
	}

	if err := os.Remove(logFile); err != nil {
		t.Fatalf("remove: %v", err)
	}
	waitForPolls()
	if err := os.WriteFile(logFile, []byte(rotationShortLine), 0644); err != nil {
		t.Fatalf("recreate log: %v", err)
	}
	if e := receiveEvent(t, w); e.User != "bob" || e.PID != 2002 {
		t.Errorf("unexpected event after the file came back: %+v", e)
	}
}

func TestFileWatcher_DropsPartialLineOnRotation(t *testing.T) {
	logFile := newEmptyLogFile(t)
	w := startTestWatcher(t, logFile, slog.Default())

	appendToFile(t, logFile, rotationLongLine+"Jan  1 12:00:01 server sshd[3003]: Failed password for ghost")
	if e := receiveEvent(t, w); e.User != "alice" {
		t.Fatalf("unexpected first event: %+v", e)
	}
	waitForPolls()

	if err := os.WriteFile(logFile, []byte(rotationShortLine), 0644); err != nil {
		t.Fatalf("truncate and rewrite: %v", err)
	}
	// Had the partial line survived, it would prefix the new line and lend
	// the event its 12:00:01 timestamp.
	e := receiveEvent(t, w)
	if e.User != "bob" || e.PID != 2002 || e.Timestamp.Format("15:04:05") != "12:00:05" {
		t.Errorf("unexpected event after rotation: %+v", e)
	}
}

func TestFileWatcher_StopsWhenReopenFails(t *testing.T) {
	logFile := newEmptyLogFile(t)
	var logs syncBuffer
	w := startTestWatcher(t, logFile, slog.New(slog.NewTextHandler(&logs, nil)))

	appendToFile(t, logFile, rotationLongLine)
	if e := receiveEvent(t, w); e.User != "alice" {
		t.Fatalf("unexpected first event: %+v", e)
	}

	// A unix socket stats as an empty file, which reads as rotation, but
	// open(2) refuses it with ENXIO, even for root.
	if err := os.Remove(logFile); err != nil {
		t.Fatalf("remove: %v", err)
	}
	listener, err := net.Listen("unix", logFile)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	defer listener.Close()

	select {
	case e, ok := <-w.Events():
		if ok {
			t.Fatalf("expected the events channel to close, got event %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for the watcher to stop")
	}
	if !strings.Contains(logs.String(), `msg="reopen file"`) {
		t.Errorf("expected a reopen warning, got logs:\n%s", logs.String())
	}
}

func TestFileWatcher_StopUnblocksPendingSend(t *testing.T) {
	logFile := newEmptyLogFile(t)
	w := startTestWatcher(t, logFile, slog.Default())

	events := w.Events()
	appendToFile(t, logFile, strings.Repeat(rotationLongLine, cap(events)+44))

	deadline := time.Now().Add(3 * time.Second)
	for len(events) < cap(events) {
		if time.Now().After(deadline) {
			t.Fatalf("events buffer never filled: %d/%d", len(events), cap(events))
		}
		time.Sleep(10 * time.Millisecond)
	}

	stopped := make(chan struct{})
	go func() {
		w.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop blocked while the watcher was waiting to send")
	}

	received := 0
	for range events {
		received++
	}
	if received != cap(events) {
		t.Errorf("expected exactly the %d buffered events before close, got %d", cap(events), received)
	}
}
