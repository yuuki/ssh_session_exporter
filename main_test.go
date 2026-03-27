//go:build linux

package main

import "testing"

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
