package collector

import (
	"context"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuuki/ssh_session_exporter/authlog"
	"github.com/yuuki/ssh_session_exporter/sessiontracker"
)

var discardLogger = slog.New(slog.DiscardHandler)

// FuzzRunAuthLogLine takes an auth log line through the whole path that
// turns it into metrics: ParseLine, Run and a scrape. Remote clients choose
// the user names sshd logs and local users can write lines through
// syslog(3); whatever a line holds, Run must not panic (that would end the
// exporter) and the scrape must succeed.
func FuzzRunAuthLogLine(f *testing.F) {
	for _, line := range []string{
		"Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 192.168.1.10 port 22 ssh2",
		"Sep  2 05:06:41 localhost sshd-session[15424]: Accepted publickey for probe from 192.168.5.2 port 59614 ssh2",
		"Jan  1 12:00:00 server sshd[3001]: Invalid user admin from 10.0.0.5 port 22",
		"Jan  1 12:00:00 server sshd[4001]: Disconnected from authenticating user root 10.0.0.1 port 22 [preauth]",
		"Jan  1 12:00:00 server sshd[3001]: Invalid user ad\xffmin from 10.0.0.5 port 22",
		"sshd[0]: Failed 0 for 0 from \xad port 0",
	} {
		f.Add(line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		event := authlog.ParseLine(line)
		if event == nil {
			return
		}
		reg := prometheus.NewPedanticRegistry()
		c, err := New(reg, &mockReader{}, sessiontracker.New(discardLogger), discardLogger)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		events := make(chan authlog.AuthEvent, 1)
		events <- *event
		close(events)
		c.Run(context.Background(), events) // returns once events is drained
		if _, err := reg.Gather(); err != nil {
			t.Fatalf("scrape after %+v failed: %v", event, err)
		}
	})
}
