# SSH Session Exporter

Prometheus exporter for monitoring SSH sessions and authentication events on Linux servers.

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ssh_sessions_active` | Gauge | `user`, `remote_ip`, `tty` | Currently active SSH sessions |
| `ssh_auth_failures_total` | Counter | `user`, `remote_ip`, `method` | SSH authentication failures |
| `ssh_connections_total` | Counter | `user`, `remote_ip` | SSH connections established |
| `ssh_disconnections_total` | Counter | `user`, `remote_ip` | SSH disconnections |
| `ssh_session_duration_seconds` | Histogram | `user` | Distribution of session durations |
| `ssh_exporter_scrape_success` | Gauge | - | Whether the last scrape was successful |

## Data Sources

- **utmp** (`/var/run/utmp`): Active session tracking, connection/disconnection detection, session duration calculation
- **auth log** (`/var/log/auth.log` or `/var/log/secure`): Authentication failure events with method details

The auth log is optional — if unavailable, the exporter continues with utmp-based metrics only.

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
| `--auth-log.path` | `/var/log/auth.log` | Path to auth log file |

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

For RHEL/CentOS, use `--auth-log.path=/var/log/secure`.

## Note on Label Cardinality

The `remote_ip` label on counters may produce high cardinality if many unique IPs connect. Use Prometheus `metric_relabel_configs` to aggregate or drop this label if needed.

## License

MIT
