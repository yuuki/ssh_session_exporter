//go:build linux

package authlog

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFileWatcher_StopClosesReopenedFile checks that the file opened after a
// rotation is the one closed on Stop, not only the file Start opened.
func TestFileWatcher_StopClosesReopenedFile(t *testing.T) {
	logFile := newEmptyLogFile(t)
	resolved, err := filepath.EvalSymlinks(logFile)
	if err != nil {
		t.Fatalf("resolve log path: %v", err)
	}
	w := NewFileWatcher(logFile, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("start watcher: %v", err)
	}

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
	// The event from the new file proves that the watcher reopened it.
	if e := receiveEvent(t, w); e.User != "bob" {
		t.Fatalf("unexpected event after rotation: %+v", e)
	}

	w.Stop()
	if open := openFDsUnder(t, filepath.Dir(resolved)); len(open) > 0 {
		t.Errorf("files still open after Stop: %v", open)
	}
}

// openFDsUnder lists the files below dir that this process holds open.
func openFDsUnder(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot list open file descriptors: %v", err)
	}
	var open []string
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue // the fd of ReadDir itself is gone by now
		}
		if strings.HasPrefix(target, dir+string(filepath.Separator)) {
			open = append(open, target)
		}
	}
	return open
}
