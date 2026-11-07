# Contributing

Bug reports, ideas and pull requests are welcome.

- For a bug, open an issue with the exporter version, the distribution, the
  flags, and the relevant `/metrics` output or log lines (redact user names and
  addresses you do not want to publish). Report vulnerabilities privately as
  described in [SECURITY.md](SECURITY.md).
- For a larger change, such as a new metric or flag, open an issue first so
  that the design can be discussed: metric names, labels and flags are a
  compatibility contract for dashboards and alerts.

## Pull requests

1. Branch from `main` and keep the change focused.
2. Add or update tests for behaviour changes. Parsers of the auth log and utmp
   have fuzz targets; extend them when you change what they accept.
3. Run `make check` (lint, workflow audit, race tests, build). Depending on what
   you touched, also run `make test-fuzz`, `make test-e2e` (Docker) or
   `make test-bpf` (root).
4. Update README.md when flags or metrics change.
5. Use short scoped commit subjects, such as `fix: ...`, `feat: ...`,
   `ci: ...`, `docs: ...` or `refactor(collector): ...`, with the reason in the
   body.

[AGENTS.md](AGENTS.md) has the full list of commands, the architecture, and
the contracts and conventions that reviews check; it applies to AI-assisted
changes too, which a human must review before they are merged.
