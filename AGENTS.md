# AGENTS.md

Guidance for coding agents (Claude Code, Codex, Copilot, ...) and humans working
in this repository. User-facing documentation is in [README.md](README.md); the
eBPF path is described in
[docs/architecture/ebpf-shell-usable.md](docs/architecture/ebpf-shell-usable.md).

## 1. Overview and architecture

Prometheus exporter for SSH session monitoring on Linux. Three independent data
sources feed the metrics:

```
/var/run/utmp ──→ utmp.Reader ──→ sessiontracker.Tracker ──→ collector.SSHCollector ──→ /metrics
                                        (snapshot diff)           ▲
/var/log/auth.log ──→ authlog.FileWatcher ──→ fanOutAuthEvents ───┤
/var/log/secure        (tail, regex parse)         └──→ sessionlatency.Probe (optional)
kernel tracepoints ──→ eBPF ring buffer ──────────────────────────┘
```

- **utmp** parses the Linux utmp binary format: 384-byte records (x86_64 and
  32-bit platforms) or 400-byte records (arm64, riscv64, loong64), chosen by
  file length and, when a length fits both, by the host's native layout.
  `session.go` defines the platform-independent `Session` type and `Reader`
  interface; `utmp.go` (`FileReader`) is Linux-only. Sessions are records of
  type `USER_PROCESS` with a non-empty `Host` (local logins are excluded).
- **authlog** tails the auth log by polling every 100 ms, follows rotation
  (copy-truncate and rename), and parses `Failed`, `Accepted`, `Invalid user`
  and preauth disconnect lines, extracting the sshd PID (`sshd`,
  `sshd-session`, `sshd-auth` tags) and the syslog timestamp.
- **sessiontracker** is a stateful diff engine: each `UpdateSessions()` call
  compares the current utmp snapshot with the tracked sessions and returns the
  new and ended ones (with duration). Session identity is the `{user, tty}`
  struct key.
- **collector** implements `prometheus.Collector`. Gauges (`ssh_sessions_active`,
  `ssh_sessions_count`, `ssh_exporter_scrape_success`) are `ConstMetric`s built
  in `Collect()`. Counters and histograms are `CounterVec`/`HistogramVec`
  registered separately and updated in `Collect()` (connections and
  disconnections from utmp deltas, short sessions, login setup time) and in the
  `Run()` goroutine (auth events). `sessionCorrelator` (`correlator.go`) does
  PID-based failure counting for `ssh_auth_attempts_before_success` (auth.log
  internal) and `{user, remoteIP}` FIFO matching for `ssh_login_setup_seconds`
  (across auth.log and utmp; PID-independent because OpenSSH privilege
  separation uses different PIDs for auth and session processes).
- **ebpf/sessionlatency** (optional, `--ebpf.shell-usable.enabled`) attaches a
  CO-RE BPF program to accept/fork/exec/tty_write/exit tracepoints (with a
  write/writev fallback), reads events from a ring buffer, and correlates them
  with auth success events to produce interactive shell latency histograms.
- **main.go** wires everything, falls back from `/var/log/auth.log` to
  `/var/log/secure` when `--auth-log.path` is not set explicitly, and fans auth
  events out to the collector and the probe.

Key design choice: the auth log watcher and the eBPF probe are optional. If
either cannot start (permissions, missing file, no BTF), the exporter keeps
serving the remaining metrics.

## 2. Directory layout

| Path | Contents |
|------|----------|
| `main.go` | Flags, wiring, HTTP server (Linux-only) |
| `authlog/` | Auth log line parser and polling file watcher |
| `utmp/` | utmp record parser (portable) and `FileReader` (Linux) |
| `sessiontracker/` | utmp snapshot diff |
| `collector/` | Prometheus collector and auth/utmp correlator |
| `ebpf/sessionlatency/` | BPF program (`bpf/probe.c`), committed bpf2go objects and bindings (`probe_bpf{el,eb}.{go,o}`), loader and correlation processor |
| `e2e/` | Docker-based e2e (`-tags e2e`), `cmd/utmpwriter` test helper, `lima/` Rocky Linux VM e2e (`-tags e2e_rocky`) |
| `dashboards/` | Grafana dashboard |
| `docs/architecture/` | Design notes |
| `.github/workflows/` | `ci.yml`, `security.yml`, `release.yml`, `complexity.yml` |

## 3. Build

```bash
make build      # GOOS=linux go build with -X main.version, writes ./ssh_session_exporter
make install    # GOOS=linux go install .
make generate-bpf  # regenerate the eBPF objects and bindings (clang, llvm-strip, libbpf headers)
```

The target binary is Linux-only. `main.go`, `utmp/utmp.go`,
`ebpf/sessionlatency/probe_linux.go` and `e2e/cmd/utmpwriter` carry
`//go:build linux`; on macOS use `GOOS=linux` for vet and build
(`GOOS=linux go build -o /dev/null .`). The Go version is pinned in `go.mod`.

The eBPF objects are committed because `go:embed` needs them; `make build`
never needs clang. `generate.go` pins bpf2go v0.22.0. The committed objects
were built with another clang (unstripped) and an older bpf2go, so
regenerating changes the shipped object; treat it as a behaviour change and
validate it with `make test-bpf` and the Rocky e2e.

## 4. Test

```bash
make test                # go test ./...
make test-race           # go test -race ./...
make test-fuzz           # every Fuzz target for FUZZTIME (default 30s); FUZZFLAGS=-parallel=2 on shared machines
make bench               # benchmarks into bench.txt (BENCH_COUNT, BENCHTIME); compare runs with benchstat
make test-bpf            # needs sudo, kernel BTF, tracefs: verifier load + attach of the embedded objects
make test-e2e            # Docker: builds e2e/Dockerfile.e2e and drives the exporter with utmpwriter
make test-integration    # test-e2e + test-bpf
make test-e2e-rocky      # Lima Rocky Linux 9.6 VM with real sshd (Linux/macOS host with limactl; CI runs it)
go test ./collector/ -run TestCollect_ActiveSessions   # a single test
```

- `utmp` parser tests are portable and run on macOS too; only `FileReader`
  and the `main` package tests need Linux.
- `make test-bpf` fails instead of skipping (it sets
  `SSH_EXPORTER_REQUIRE_BPF=1`); `make test-bpf BPF_REQUIRE=` skips what the
  host cannot do. Without root, `go test` skips `TestProbeLoadAndAttach`.
- Fuzz targets: `FuzzParseLine`, `FuzzSplitLines` (authlog),
  `FuzzParseRecords`, `FuzzParseRecordsRoundTrip` (utmp),
  `FuzzRunAuthLogLine`, `FuzzCollectUtmpRecord` (collector, end to end to a
  scrape), `FuzzProcessorDrainsState` (eBPF correlation state). Crashers found
  by fuzzing are kept under `testdata/fuzz/<Target>/` as regression seeds.
- `goleak.VerifyTestMain` guards the `main`, `authlog`, `collector` and
  `sessionlatency` packages: a test must stop every goroutine it starts.
- Rocky e2e environment variables: `ROCKY_LIMA_INSTANCE_PREFIX`,
  `ROCKY_LIMA_KEEP_FAILED=1`, `ROCKY_LIMA_METRICS_PORT`, `ROCKY_LIMA_SSH_PORT`.
  It deliberately avoids Lima `--plain` (it needs Lima-managed SSH config, port
  forwarding and `limactl copy`). Failure artifacts go to
  `.e2e-artifacts/rocky-lima/<instance>/`.
- Docker e2e: `E2E_PORT` picks the host port; set `COMPOSE_PROJECT_NAME` on a
  shared Docker daemon.

Testing patterns:

- Mock interfaces: `utmp.Reader` is mocked in collector tests (`mockReader`).
- Time injection: `Tracker.now` and the eBPF `processor.now` are
  `func() time.Time` fields replaced in tests; prefer them over sleeps.
- Prometheus assertions: `testutil.CollectAndCompare` for a collector,
  `testutil.GatherAndCompare` for a registry. Trigger `Collect()` before
  `GatherAndCompare` to avoid gather-ordering races with the `CounterVec`s.
- File-based tests: watcher tests create files with `t.TempDir()` and append
  lines.

## 5. Static analysis

```bash
make lint          # golangci-lint (.golangci.yml, Linux view) + go mod tidy -diff
make fmt           # golangci-lint fmt (gofmt)
make vet           # GOOS=linux go vet ./...
make lint-actions  # actionlint + zizmor (online audits only when GH_TOKEN is set)
make vuln          # govulncheck ./... (Linux view)
make complexity    # cccc ranking (needs cccc; CI tracks scores with octocov)
```

Tool versions are pinned in the Makefile and in the workflows; bump them
together. The go-run tools are built with this module's toolchain
(`go env GOVERSION`), because golangci-lint refuses a module that targets a
newer Go than it was built with. With `GH_TOKEN` set but the GitHub API
unreachable, run `env -u GH_TOKEN make check`.

## 6. Coding conventions

- Logging: `log/slog` (`logger.Info/Warn/Error/Debug` with key-value pairs).
  Per-session detail goes to Debug.
- Errors: wrap with `fmt.Errorf("...: %w", err)`; optional features log a
  warning and continue instead of exiting.
- Comments and docs in English; comments say why, not what.
- Commits: short scoped subjects such as `fix: ...`, `fix(e2e): ...`,
  `feat: ...`, `ci: ...`, `docs: ...`, `chore: ...`, `refactor(scope): ...`,
  `perf(scope): ...`.

## 7. Compatibility contracts

Changing any of these is a user-visible change; call it out in the PR.

- **Metrics** (names, types, labels; descriptions in the README):

  | Metric | Type | Labels |
  |--------|------|--------|
  | `ssh_sessions_active` | Gauge | user, remote_ip, tty |
  | `ssh_sessions_count` | Gauge | — |
  | `ssh_exporter_scrape_success` | Gauge | — |
  | `ssh_auth_failures_total` | Counter | user, remote_ip, method |
  | `ssh_auth_success_total` | Counter | user, remote_ip, method |
  | `ssh_invalid_user_attempts_total` | Counter | user, remote_ip |
  | `ssh_preauth_disconnects_total` | Counter | user, remote_ip |
  | `ssh_connections_total` | Counter | user, remote_ip |
  | `ssh_disconnections_total` | Counter | user, remote_ip |
  | `ssh_short_sessions_total` | Counter | user, remote_ip |
  | `ssh_session_duration_seconds` | Histogram | user |
  | `ssh_login_setup_seconds` | Histogram | user |
  | `ssh_auth_attempts_before_success` | Histogram | user |
  | `ssh_accept_to_shell_usable_seconds` | Histogram | user, remote_ip |
  | `ssh_accept_to_child_fork_seconds` | Histogram | user, remote_ip |
  | `ssh_child_fork_to_shell_exec_seconds` | Histogram | user, remote_ip |
  | `ssh_shell_exec_to_first_tty_output_seconds` | Histogram | user, remote_ip |
  | `ssh_shell_usable_failures_total` | Counter | stage |
  | `ssh_exporter_ebpf_shell_usable_up` | Gauge | — |

  Defined in `collector/collector.go` and `ebpf/sessionlatency/processor.go`;
  histogram buckets are part of the contract too.
- **CLI flags** (`main.go`, README table): `--web.listen-address` (`:9842`),
  `--web.telemetry-path`, `--utmp.path`, `--auth-log.path`,
  `--ebpf.shell-usable.enabled`, `--ebpf.shell-usable.timeout`, `--version`.
- **Input formats**: the utmp layouts in `utmp/parser.go` (mirrored by
  `e2e/cmd/utmpwriter`), and the OpenSSH log formats matched by the regexes in
  `authlog/parser.go`.
- **BPF ABI**: `struct event` in `ebpf/sessionlatency/bpf/probe.c` (80 bytes,
  little-endian, `ts_ns` 8-byte aligned) ↔ `rawEvent` in `probe_linux.go`,
  decoded with `binary.Read` (which adds no padding, so padding is explicit).
  `TestRawEventMatchesBPFEventSize` checks the size against the embedded
  object; the `EVENT_*` values ↔ `traceEventKind`.
- Label values are always valid UTF-8: the parsers replace invalid bytes with
  U+FFFD (client_golang panics or fails the scrape otherwise).

## 8. Concurrency and resource management

- Goroutines and their owners: `FileWatcher.run` (stopped by `Stop()` or the
  context; closes the events channel and the file it is reading),
  `SSHCollector.Run` and `RunCleanup` (end with the context or a closed
  channel), `fanOutAuthEvents` (closes the collector channel when it ends),
  and the probe's ring buffer reader, cleanup loop and context watcher
  (`Probe.Close` waits for them).
- Locks: `sessionCorrelator.mu`, `Tracker.mu` and `processor.mu` guard their
  maps. Keep syscalls and channel operations out of them (`Tracker` only logs
  at Debug level under its lock; `processor.resolveUser`, which would look up
  `/etc/passwd`, is currently unused).
- A scrape reads utmp and diffs it (`Collect`); it must stay cheap and must
  not block on the auth log or the probe.
- Memory is bounded by expiry: the correlator drops entries after 5 minutes
  (`RunCleanup`, every minute), the eBPF processor after its timeout
  (`cleanupInterval` 5 s). Keep new state on the same footing.

## 9. Performance constraints

- `ParseLine` runs on every auth log line (RE2 regexes, linear time); lines
  without `sshd` return after one `strings.Contains`. Benchmarks:
  `BenchmarkParseLine`, `BenchmarkParseRecords`, `BenchmarkCollect`.
- Cardinality: `user` and `remote_ip` come from the network (attackers choose
  user names in `Invalid user` lines and their source IPs). Do not add
  per-connection labels (PID, port, TTY on counters); users relabel or drop
  `remote_ip` as the README explains.
- The eBPF programs run in kernel context on hot paths (every accept, fork,
  exec, write); keep their filtering in the kernel.

## 10. Before opening a PR

- `make check` (lint, lint-actions, test-race, build) must pass.
- Parsers (`authlog/`, `utmp/`): also `make test-fuzz`.
- Collector, authlog or utmp output: also `make test-e2e`.
- `ebpf/`: also `make test-bpf`; after editing `bpf/probe.c`, `make
  generate-bpf` and commit the regenerated `probe_bpf{el,eb}.{go,o}`; rely on
  the CI `test-e2e-rocky` job for a real kernel and sshd.
- User-visible changes: update README (flags, metrics) and this file.

## 11. Rules for AI agents

Forbidden:

- Disabling, skipping or weakening tests, fuzz properties or lint rules to get
  green; hiding failures (`|| true`, `continue-on-error`, broad excludes).
- Editing generated files by hand (`probe_bpf*.go`, `*.o`); regenerate them.
- Adding dependencies without a stated reason; test-only ones included.
- Changing the contracts in §7 without calling it out.
- Loosening workflow permissions, unpinning actions, or adding caches to the
  release workflow.
- Committing secrets, rewriting history, force-pushing, tagging or publishing
  releases.

## 12. Changes that need human review

Even with green CI: workflow and release files; permissions and secrets; the
eBPF program and its loader (runs as root, in the kernel); parsers of
untrusted input (`authlog`, `utmp`); the BPF event ABI; metric names, labels
and flags; dependency additions; large refactors.
