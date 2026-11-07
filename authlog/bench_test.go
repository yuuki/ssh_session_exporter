package authlog

import "testing"

// Every auth log line passes through ParseLine; most are not SSH events.
func BenchmarkParseLine(b *testing.B) {
	for _, bc := range []struct{ name, line string }{
		{"invalid_user", "Jan  1 12:00:00 server sshd[3001]: Invalid user admin from 10.0.0.5 port 22"},
		{"accepted", "Sep  2 05:06:41 localhost sshd-session[15424]: Accepted publickey for probe from 192.168.5.2 port 59614 ssh2"},
		{"sshd_unmatched", "Jan  1 12:05:00 server sshd[1234]: Connection closed by 10.0.0.5 port 54321"},
		{"not_sshd", "Jan  1 12:00:00 server systemd[1]: Started Session 1 of user alice."},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				ParseLine(bc.line)
			}
		})
	}
}
