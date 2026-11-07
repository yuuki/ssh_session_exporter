# AGENTS.md

## Rules
- The auth log watcher and the eBPF probe are optional: when one cannot start (permissions, missing file, no BTF), warn and keep serving; never exit.
- `user` (from `Invalid user` lines) and `remote_ip` are chosen by attackers: never add per-connection labels (PID, port, TTY on counters).
- The committed eBPF objects were built with another clang and an older bpf2go: regenerating them changes the shipped object, a behaviour change.

## Compatibility contracts
- Metric names, types, labels and histogram buckets (`collector/collector.go`, `ebpf/sessionlatency/processor.go`); CLI flags (`main.go`).
- utmp layouts: `utmp/parser.go` ↔ `e2e/cmd/utmpwriter`; OpenSSH log formats: the regexes in `authlog/parser.go`.
- BPF ABI: `struct event` in `ebpf/sessionlatency/bpf/probe.c` ↔ `rawEvent` in `probe_linux.go`; `EVENT_*` ↔ `traceEventKind`.

## Before opening a pull request
- `make check`; also `make test-fuzz` for `authlog/` or `utmp/`, and `make test-e2e` (Docker) for collector, authlog or utmp output.
- `ebpf/`: also `make test-bpf` (root); after `make generate-bpf`, the Rocky e2e (`make test-e2e-rocky`, or the CI `test-e2e-rocky` job).

## Git conventions
- Branches: `<type>/<issue>-<summary>` (`<type>/<summary>` without an issue); tools' `agent/*`, `claude/*`, `copilot/*`, `dependabot/*` keep their names.
- Commits and PR titles: Conventional Commits 1.0.0, types `feat` `fix` `perf` `refactor` `test` `docs` `build` `ci` `chore` `revert`; scopes: `collector`, `authlog`, `utmp`, `sessiontracker`, `sessionlatency`, `ebpf`, `e2e`.
