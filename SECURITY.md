# Security policy

ssh_session_exporter usually runs as root on SSH servers, bastion hosts
included: it reads `/var/run/utmp` and the auth log, and, when
`--ebpf.shell-usable.enabled` is set, loads eBPF programs into the kernel. Much
of what it parses is chosen by others: remote clients pick the user names that
sshd logs, and local users can write to the auth log through syslog(3) and to
utmp through libutempter. Security issues are taken seriously.

In scope, for example:

- input in the auth log or utmp that crashes the exporter, makes `/metrics`
  fail, or makes it report sessions or logins that did not happen through sshd
  beyond what a forged log line can claim;
- unbounded memory or CPU use driven by remote clients;
- problems in the eBPF programs or their loader;
- the HTTP endpoint exposing more than the metrics.

Known limits that are documented and not vulnerabilities: anyone who can write
to the auth log can forge the lines the exporter counts, and the `user` and
`remote_ip` labels follow what remote clients send, so their cardinality is
theirs to grow (see "Note on Label Cardinality" in the README). Ideas to reduce
them are welcome as regular issues.

## Supported versions

Security fixes are made on the `main` branch and released in the next version.
Only the latest release is supported.

## Reporting a vulnerability

Please do **not** open a public issue, pull request or discussion.

Report the vulnerability privately with GitHub's
[private vulnerability reporting](https://github.com/yuuki/ssh_session_exporter/security/advisories/new)
(the "Report a vulnerability" button of the Security tab). If that is not
possible, contact the author privately via the contact information on
https://github.com/yuuki.

Please include the exporter version (`ssh_session_exporter --version`), the
flags it runs with, the distribution and OpenSSH version, what an attacker
controls (a remote SSH client, a local account, the log pipeline, ...), a
sample of the input involved, and the impact. You should receive an answer
within a few weeks; the project is maintained on a best-effort basis.
