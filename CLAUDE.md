# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
make build          # Cross-compile for Linux (GOOS=linux)
make test           # go test ./...
make vet            # GOOS=linux go vet ./...
go test ./authlog/  # Run tests for a single package
go test ./collector/ -run TestCollect_ActiveSessions  # Run a single test
GOOS=linux go vet ./...   # Vet all packages (must target Linux)
GOOS=linux go build -o /dev/null .  # Verify compilation
```

The `utmp` and `cmd` packages have `//go:build linux` constraints. Use `GOOS=linux` for vet/build. Tests in `utmp/` are skipped on macOS — this is expected.

## Architecture

Prometheus exporter for SSH session monitoring on Linux. Two independent data sources feed into a single collector:

```
/var/run/utmp ──→ utmp.Reader ──→ sessiontracker.Tracker ──→ collector.SSHCollector ──→ /metrics
                                        (snapshot diff)           │
/var/log/auth.log ──→ authlog.FileWatcher ─── chan AuthEvent ─────┘
                        (tail, regex parse)
```

**utmp** — Parses Linux utmp binary format (384-byte records). `session.go` defines platform-independent types (`Session`, `Reader` interface); `utmp.go` contains Linux-specific binary parsing. Sessions are identified by non-empty `Host` field (excludes local logins).

**authlog** — Tails auth log with `nxadm/tail` (handles log rotation). Only parses `Failed` auth lines — success/disconnect events are intentionally excluded because connection lifecycle is tracked via utmp diffs instead.

**sessiontracker** — Stateful diff engine. Each `UpdateSessions()` call compares the current utmp snapshot against previously tracked sessions, returning a `SessionDelta` with new and ended sessions (including duration). Uses struct key `{user, tty}` for collision-safe session identity.

**collector** — Implements `prometheus.Collector`. Gauges (`ssh_sessions_active`, `ssh_sessions_total`) are emitted as `ConstMetric` in `Collect()`. Counters/histograms (`CounterVec`/`HistogramVec`) are registered separately and updated in `Collect()` (connection/disconnection from utmp deltas) and `Run()` goroutine (auth failures from channel).

**Key design choice**: The auth log watcher is optional — if it fails to start (permissions, missing file), the exporter continues with utmp-based metrics only.

## Metrics

| Metric | Type | Labels |
|--------|------|--------|
| `ssh_sessions_active` | Gauge | user, remote_ip, tty |
| `ssh_sessions_count` | Gauge | — |
| `ssh_auth_failures_total` | Counter | user, remote_ip, method |
| `ssh_connections_total` | Counter | user, remote_ip |
| `ssh_disconnections_total` | Counter | user, remote_ip |
| `ssh_session_duration_seconds` | Histogram | user |

## Release Procedure

Releases are triggered by pushing a semver tag. GitHub Actions builds binaries for four architectures and publishes them as a GitHub Release automatically.

```bash
# 1. Ensure main is clean and tests pass
git checkout main
git pull
make test
make vet

# 2. Create and push a tag
git tag v1.2.3
git push origin v1.2.3
```

The `release.yml` workflow will:
- Build `ssh_session_exporter` for `linux/amd64`, `linux/arm64`, `linux/armv7`, `linux/386`
- Package each binary as `ssh_session_exporter-<tag>-<arch>.tar.gz`
- Generate `checksums.txt` (SHA-256)
- Create a GitHub Release with auto-generated release notes

The binary embeds the tag as its version string (accessible via `ssh_session_exporter --version`).

To verify locally before tagging:
```bash
VERSION=v1.2.3 make build
./ssh_session_exporter --version   # should print v1.2.3
```

## Testing Patterns

- **Mock interfaces**: `utmp.Reader` is mocked in collector tests via `mockReader`
- **Time injection**: `Tracker.now` is a `func() time.Time` field, replaced in tests
- **Prometheus assertions**: Use `testutil.CollectAndCompare` for Collector metrics, `testutil.GatherAndCompare` for registry-wide metrics. Trigger `Collect()` manually before `GatherAndCompare` to avoid gather-ordering races with `CounterVec`
- **File-based tests**: Watcher tests create temp files with `t.TempDir()` and append log lines
