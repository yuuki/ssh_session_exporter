package collector

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuuki/ssh_session_exporter/sessiontracker"
	"github.com/yuuki/ssh_session_exporter/utmp"
)

// BenchmarkCollect measures a steady-state scrape: the sessions are already
// tracked, so the cost is the utmp diff and the gauge emission.
func BenchmarkCollect(b *testing.B) {
	sessions := make([]utmp.Session, 100)
	login := time.Unix(1_700_000_000, 0)
	for i := range sessions {
		sessions[i] = utmp.Session{User: fmt.Sprintf("user%d", i%10), TTY: fmt.Sprintf("pts/%d", i), Host: fmt.Sprintf("192.0.2.%d", i), LoginTime: login}
	}
	tracker := sessiontracker.New(slog.New(slog.DiscardHandler))
	tracker.Initialize(sessions)
	c, err := New(prometheus.NewRegistry(), &mockReader{sessions: sessions}, tracker, slog.New(slog.DiscardHandler))
	if err != nil {
		b.Fatal(err)
	}
	ch := make(chan prometheus.Metric, len(sessions)+2)
	b.ReportAllocs()
	for b.Loop() {
		c.Collect(ch)
		for len(ch) > 0 {
			<-ch
		}
	}
}
