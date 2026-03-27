# SSH Session Exporter
[![AI Generated](https://img.shields.io/badge/AI%20Generated-Claude-orange?logo=anthropic)](https://claude.ai/claude-code)
[![License](https://img.shields.io/github/license/yuuki/ssh_sesshon_exporter)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/yuuki/ssh_sesshon_exporter)](https://github.com/yuuki/ssh_sesshon_exporter/releases)
[![Go](https://img.shields.io/badge/Go-%3E%3D1.26-blue?logo=go)](https://go.dev)

Prometheus exporter for monitoring SSH sessions and authentication events on Linux servers.

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ssh_sessions_active` | Gauge | `user`, `remote_ip`, `tty` | Currently active SSH sessions |
| `ssh_sessions_count` | Gauge | - | Total number of currently active SSH sessions |
| `ssh_auth_failures_total` | Counter | `user`, `remote_ip`, `method` | SSH authentication failures |
| `ssh_connections_total` | Counter | `user`, `remote_ip` | SSH connections established (detected via utmp diff) |
| `ssh_disconnections_total` | Counter | `user`, `remote_ip` | SSH disconnections (detected via utmp diff) |
| `ssh_session_duration_seconds` | Histogram | `user` | Distribution of session durations |
| `ssh_exporter_scrape_success` | Gauge | - | Whether the last scrape was successful |

## Data Sources

- **utmp** (`/var/run/utmp`): Active session tracking, connection/disconnection detection, session duration calculation
- **auth log** (`/var/log/auth.log` or `/var/log/secure`): Authentication failure events with method details

The auth log is optional — if unavailable, the exporter continues with utmp-based metrics only.

### Limitations of utmp-based event detection

Connection/disconnection counters (`ssh_connections_total`, `ssh_disconnections_total`) and session duration (`ssh_session_duration_seconds`) are derived by diffing utmp snapshots between scrapes. This means:

- Sessions that start and end between two scrapes are not observed.
- Pre-existing sessions at exporter startup are treated as baseline and not counted as new connections. Their disconnections are counted if they end while the exporter is running.

## Installation

```bash
go install github.com/yuuki/ssh_sesshon_exporter/cmd/ssh_session_exporter@latest
```

Or build from source:

```bash
make build
```

## Usage

```bash
ssh_session_exporter [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--web.listen-address` | `:9842` | Address to listen on |
| `--web.telemetry-path` | `/metrics` | Path for metrics endpoint |
| `--utmp.path` | `/var/run/utmp` | Path to utmp file |
| `--auth-log.path` | `/var/log/auth.log` | Path to auth log file. When not explicitly set, the exporter also falls back to `/var/log/secure` if present |

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

When `--auth-log.path` is left at its default, the exporter automatically uses `/var/log/secure` on RHEL/CentOS if `/var/log/auth.log` does not exist. If you set `--auth-log.path` explicitly, that path is used as-is.

## Note on Label Cardinality

The `remote_ip` label on counters may produce high cardinality if many unique IPs connect. Use Prometheus `metric_relabel_configs` to aggregate or drop this label if needed.

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
