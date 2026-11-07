# AGENTS.md

This file holds only what the code does not show. The eBPF path is designed
in [docs/architecture/ebpf-shell-usable.md](docs/architecture/ebpf-shell-usable.md).

## Rules the code does not show

- The auth log watcher and the eBPF probe are optional: when one cannot start
  (permissions, missing file, no BTF), log a warning and keep serving the
  other metrics; never exit.
- A scrape (`Collect`) stays cheap and never blocks on the auth log or probe.
- Keep syscalls and channel operations out of `sessionCorrelator.mu`,
  `Tracker.mu` and `processor.mu`.
- Bound every new piece of correlation state by expiry, as the correlator and
  the eBPF processor do.
- Keep the eBPF programs' filtering in the kernel: they run on every accept,
  fork, exec and write.
- Label values are always valid UTF-8 (parsers replace invalid bytes with
  U+FFFD): client_golang panics or fails the scrape otherwise.
- Cardinality: attackers choose `user` (in `Invalid user` lines) and
  `remote_ip`. Never add per-connection labels (PID, port, TTY on counters).
- Regenerating the eBPF objects changes the shipped object (the committed ones
  were built with another clang and an older bpf2go): validate with
  `make test-bpf` and the Rocky e2e.
- English for code, comments and docs.

## Compatibility contracts

A change is user-visible: call it out in the PR.

- Metric names, types, labels and histogram buckets: `collector/collector.go`,
  `ebpf/sessionlatency/processor.go`; README and `dashboards/` use them.
- CLI flags: `main.go`.
- utmp layouts: `utmp/parser.go`, mirrored by `e2e/cmd/utmpwriter`; change
  both together.
- OpenSSH log formats: the regexes in `authlog/parser.go`.
- BPF ABI: `struct event` in `ebpf/sessionlatency/bpf/probe.c` ↔ `rawEvent`
  in `ebpf/sessionlatency/probe_linux.go`, with explicit padding because
  `binary.Read` adds none; `EVENT_*` ↔ `traceEventKind`.

## Before opening a pull request

- `make check`.
- Parsers (`authlog/`, `utmp/`): also `make test-fuzz`.
- Collector, authlog or utmp output: also `make test-e2e` (Docker).
- `ebpf/`: also `make test-bpf` (root). After editing `bpf/probe.c`, run
  `make generate-bpf` and commit the regenerated `probe_bpf{el,eb}.{go,o}`;
  the CI `test-e2e-rocky` job covers a real kernel and sshd.
- User-visible changes (flags, metrics): update README.

## Git conventions

Branches: `<type>/<issue>-<summary>`, or `<type>/<summary>` without an issue
(`fix/166-connect-errors`, `feat/qp-counters`). `<type>` is a commit type
below; `<summary>` is 2–5 lowercase ASCII words joined by `-`. Branches named
by tools keep their names (`agent/*`, `claude/*`, `copilot/*`,
`dependabot/*`). Never push to the default branch.

Commits follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

    <type>(<scope>)!: <subject>

    <body>

    <footer>

- `type`: `feat` (new user-visible behaviour), `fix` (bug fix), `perf`,
  `refactor` (no behaviour change), `test`, `docs`, `build` (build system,
  dependencies, packaging), `ci` (workflows), `chore` (anything else, e.g.
  `chore(release): prepare v1.2.3`), `revert`.
- `scope`: optional; the package or area changed: `collector`, `authlog`,
  `utmp`, `sessiontracker`, `sessionlatency`, `ebpf`, `e2e`.
- `!` and a `BREAKING CHANGE: <what changed and how to migrate>` footer for
  any change to a compatibility contract above.
- `subject`: imperative, lower case (except identifiers), no final period,
  at most 72 characters including the prefix.
- `body`: why the change is needed and what it affects, wrapped at 72
  columns; required unless the subject says everything.
- `footer`: `Fixes #N` / `Refs #N`, `BREAKING CHANGE:`, trailers such as
  `Co-Authored-By:`.
- One logical change per commit; regenerated files go in the commit that
  changes their source. Pull request titles use the same format (they become
  the squash commit).

## Forbidden

- Disabling, skipping or weakening tests, fuzz properties or lint rules to get
  green; hiding failures (`|| true`, `continue-on-error`, broad excludes).
- Editing generated files by hand (`probe_bpf*.go`, `*.o`); regenerate them.
- Adding dependencies, test-only ones included, without a stated reason.
- Changing a compatibility contract without calling it out.
- Loosening workflow permissions, unpinning actions, or adding caches to the
  release workflow.
- Committing secrets, rewriting history, force-pushing, tagging or publishing
  releases.

## Needs human review

Even with green CI: workflow and release files; permissions and secrets; the
eBPF program and its loader (root, in the kernel); parsers of untrusted input
(`authlog`, `utmp`); the BPF event ABI; metric names, labels and flags;
dependency additions; large refactors.

## Environment notes

- With `GH_TOKEN` set but the GitHub API unreachable, run
  `env -u GH_TOKEN make check`.
- On a shared Docker daemon, set `COMPOSE_PROJECT_NAME` (and `E2E_PORT`) for
  `make test-e2e`.
