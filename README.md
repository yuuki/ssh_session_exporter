# SSH Session Exporter

[![AI Generated](https://img.shields.io/badge/AI%20Generated-Claude-orange?logo=anthropic)](https://claude.ai/claude-code)
[![License](https://img.shields.io/github/license/yuuki/ssh_session_exporter)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/yuuki/ssh_session_exporter)](https://github.com/yuuki/ssh_session_exporter/releases)
[![Go](https://img.shields.io/badge/Go-%3E%3D1.26-blue?logo=go)](https://go.dev)

Prometheus exporter for SSH session and authentication monitoring on Linux servers. Exposes session lifecycle metrics (active sessions, durations, connection events) from `/var/run/utmp` and authentication metrics (failures, invalid users, pre-auth disconnects) from `/var/log/auth.log`.

## Installation

```bash
go install github.com/yuuki/ssh_session_exporter/cmd/ssh_session_exporter@latest
```

Or build from source:

```bash
make build
```

### Rocky Linux 9.6 Reproduction E2E

For production-faithful SSH login reproduction on Linux or macOS, a separate Lima-based E2E suite boots a Rocky Linux 9.6 VM and uses a real `sshd`, `/var/log/secure`, and `utmp`. The same suite also runs in GitHub Actions on a dedicated Ubuntu job via Lima.

Prerequisites:

- `limactl` 2.0+
- `ssh`
- Linux or macOS host with Lima support

Run:

```bash
make test-e2e-rocky
```

Optional environment variables:

- `ROCKY_LIMA_INSTANCE_PREFIX` - Lima instance name prefix
- `ROCKY_LIMA_KEEP_FAILED=1` - Keep the VM after a failed run
- `ROCKY_LIMA_METRICS_PORT` - Host port forwarded to guest `:9842`
- `ROCKY_LIMA_SSH_PORT` - Host port used for the Lima SSH endpoint

Failure artifacts are written to `.e2e-artifacts/rocky-lima/<instance>/`.

## Usage

```bash
ssh_session_exporter [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--web.listen-address` | `:9842` | Address to listen on |
| `--web.telemetry-path` | `/metrics` | Path for metrics endpoint |
| `--utmp.path` | `/var/run/utmp` | Path to utmp file |
| `--auth-log.path` | `/var/log/auth.log` | Path to auth log file. When not explicitly set, falls back to `/var/log/secure` if present |
| `--ebpf.shell-usable.enabled` | `false` | Enable eBPF-based interactive shell latency metrics |
| `--ebpf.shell-usable.timeout` | `30s` | Timeout for eBPF shell latency correlation |

### Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'ssh'
    static_configs:
      - targets: ['localhost:9842']
```

## systemd

```ini
[Unit]
Description=Prometheus SSH Session Exporter
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ssh_session_exporter
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Reading `/var/log/auth.log` requires root or membership in the `adm` group (Debian/Ubuntu).
The optional eBPF shell latency probe also typically requires running as root. In addition, the host kernel must expose BTF metadata (for example `/sys/kernel/btf/vmlinux`) so the bundled CO-RE object can attach.

When `--auth-log.path` is left at its default, the exporter automatically uses `/var/log/secure` on RHEL/CentOS if `/var/log/auth.log` does not exist. If you set `--auth-log.path` explicitly, that path is used as-is.

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ssh_sessions_active` | Gauge | `user`, `remote_ip`, `tty` | Currently active SSH sessions |
| `ssh_sessions_count` | Gauge | - | Total number of currently active SSH sessions |
| `ssh_auth_failures_total` | Counter | `user`, `remote_ip`, `method` | SSH authentication failures |
| `ssh_auth_success_total` | Counter | `user`, `remote_ip`, `method` | Successful SSH authentications |
| `ssh_invalid_user_attempts_total` | Counter | `user`, `remote_ip` | SSH authentication attempts for invalid users |
| `ssh_preauth_disconnects_total` | Counter | `user`, `remote_ip` | SSH disconnections before authentication completed |
| `ssh_connections_total` | Counter | `user`, `remote_ip` | SSH connections established (detected via utmp diff) |
| `ssh_disconnections_total` | Counter | `user`, `remote_ip` | SSH disconnections (detected via utmp diff) |
| `ssh_short_sessions_total` | Counter | `user`, `remote_ip` | SSH sessions that ended within 30 seconds |
| `ssh_session_duration_seconds` | Histogram | `user` | Distribution of SSH session durations |
| `ssh_login_setup_seconds` | Histogram | `user` | Time from authentication success to session appearing in utmp |
| `ssh_auth_attempts_before_success` | Histogram | `user` | Failed authentication attempts before a successful login |
| `ssh_accept_to_shell_usable_seconds` | Histogram | `user`, `remote_ip` | Time from `accept()` to the first PTY output for interactive SSH sessions |
| `ssh_accept_to_child_fork_seconds` | Histogram | `user`, `remote_ip` | Time from `accept()` to the initial per-session sshd child fork |
| `ssh_child_fork_to_shell_exec_seconds` | Histogram | `user`, `remote_ip` | Time from the initial per-session sshd child fork to shell exec |
| `ssh_shell_exec_to_first_tty_output_seconds` | Histogram | `user`, `remote_ip` | Time from shell exec to the first PTY output |
| `ssh_shell_usable_failures_total` | Counter | `stage` | Failures in eBPF shell latency correlation |
| `ssh_exporter_ebpf_shell_usable_up` | Gauge | - | Whether the eBPF shell latency probe is attached and running |
| `ssh_exporter_scrape_success` | Gauge | - | Whether the last scrape was successful |

### Note on Label Cardinality

The `remote_ip` label on counters may produce high cardinality if many unique IPs connect. Use Prometheus `metric_relabel_configs` to aggregate or drop this label if needed.
The eBPF latency histograms also include `remote_ip`, which can create a large number of time series on bastion hosts or Internet-facing SSH endpoints. Use relabeling aggressively if you do not need per-IP latency histograms.

### eBPF shell latency semantics

- The eBPF latency metrics only target **interactive PTY sessions**. Non-interactive sessions such as `scp`, `sftp`, and `ssh host cmd` are intentionally excluded.
- `ssh_accept_to_shell_usable_seconds` uses the first PTY write as the "shell usable" proxy. This is close to user-perceived readiness, but it is not a literal prompt-render timestamp.
- If the eBPF probe fails to attach, the exporter continues to expose the existing auth-log and utmp metrics, and `ssh_exporter_ebpf_shell_usable_up` remains `0`.

### Limitations of utmp-based event detection

Connection/disconnection counters (`ssh_connections_total`, `ssh_disconnections_total`) and session duration (`ssh_session_duration_seconds`) are derived by diffing utmp snapshots between scrapes. This means:

- Sessions that start and end between two scrapes are not observed.
- Pre-existing sessions at exporter startup are treated as baseline and not counted as new connections. Their disconnections are counted if they end while the exporter is running.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ssh_session_exporter                         │
│                                                                     │
│  /var/run/utmp ──→ utmp.Reader ──→ sessiontracker.Tracker ──┐      │
│                    (binary parse)    (snapshot diff)         │      │
│                                                              ▼      │
│                                                   collector.SSHCollector ──→ /metrics
│                                                              ▲      │
│  /var/log/auth.log ──→ authlog.FileWatcher ──→ chan AuthEvent┘      │
│  /var/log/secure       (tail + parse)                               │
│  (optional)                                                         │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Sources

- **utmp** (`/var/run/utmp`): Active session tracking, connection/disconnection detection, session duration calculation
- **auth log** (`/var/log/auth.log` or `/var/log/secure`): Authentication failure events with method details

The auth log is optional — if unavailable, the exporter continues with utmp-based metrics only.

### Components

| Component | Role |
|-----------|------|
| **utmp.Reader** | Parses the Linux utmp binary format (384-byte records). Identifies SSH sessions as entries with a non-empty `Host` field. |
| **sessiontracker.Tracker** | Stateful snapshot diff engine. Each `UpdateSessions()` call compares the current utmp snapshot against the previous state and returns a `SessionDelta` containing new and ended sessions (with duration). |
| **authlog.FileWatcher** | Tails the auth log via polling (handles log rotation). Parses `Failed`, `Accepted`, `Invalid user`, and preauth disconnect lines, extracts the sshd PID and syslog timestamp, and sends `AuthEvent` values to a channel. |
| **collector.SSHCollector** | Implements `prometheus.Collector`. Processes utmp deltas on each scrape and consumes auth events in a background goroutine. Uses the PID correlator to compute metrics that span both data sources. |
| **pidCorrelator** | Tracks per-PID state (failure count, auth-accept timestamp). Records the gap between authentication success and utmp entry appearance as `ssh_login_setup_seconds`, and the number of failures before success as `ssh_auth_attempts_before_success`. |

On each Prometheus scrape, `Collect()` reads a fresh utmp snapshot, diffs it against the previous one, and derives connection/disconnection events and session durations. Auth log processing runs in a separate goroutine and updates counters immediately as each `AuthEvent` arrives.

## For Developers

### Release Procedure

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

## License

MIT
