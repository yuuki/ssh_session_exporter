package sessionlatency

import (
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuuki/ssh_session_exporter/authlog"
)

// FuzzProcessorDrainsState drives the processor with an arbitrary interleaving
// of trace and auth events: kernel events arrive in any order across CPUs,
// and remote clients control when connections and logins happen. It checks
// that the correlation state, which lives as long as the exporter, is empty
// once every process has exited and the timeout has passed, and that a
// finished session always observes all four histograms.
//
// Each op is 4 bytes: kind, a, b, and c, where c also advances the clock by
// c*10ms. PIDs come from a small set so that they collide.
func FuzzProcessorDrainsState(f *testing.F) {
	f.Add([]byte{
		0, 0, 0, 1, // accept on listener 10 from 192.0.2.1
		1, 0, 0x80, 1, // fork 100 from listener 10
		5, 0, 0, 0, // auth success alice, pid 100, 192.0.2.1
		1, 1, 0, 1, // fork 101 from 100
		2, 1, 0, 1, // exec bash in 101
		3, 1, 1, 1, // tty write by 101
	})
	f.Add([]byte{
		0, 1, 1, 1, // accept on listener 11 from 192.0.2.2
		1, 2, 0x81, 1, // fork 102 from listener 11
		3, 2, 1, 1, // tty write before exec and auth
		4, 2, 0, 1, // 102 exits
		5, 3, 1, 1, // auth success bob, pid 103 (privsep split)
		6, 0, 0, 255, // cleanup
	})

	const timeout = 30 * time.Second
	ips := []string{"192.0.2.1", "192.0.2.2", ""}
	users := []string{"alice", "bob"}
	comms := []string{"bash", "/usr/sbin/sshd"}

	f.Fuzz(func(t *testing.T, ops []byte) {
		reg := prometheus.NewPedanticRegistry()
		p, err := newProcessor(reg, slog.New(slog.DiscardHandler), Options{Timeout: timeout})
		if err != nil {
			t.Fatalf("newProcessor: %v", err)
		}
		now := time.Unix(1_700_000_000, 0)
		p.now = func() time.Time { return now }

		seen := map[int32]struct{}{}
		pid := func(x byte) int32 {
			v := 100 + int32(x%6)
			seen[v] = struct{}{}
			return v
		}
		listener := func(x byte) int32 {
			v := 10 + int32(x%2)
			seen[v] = struct{}{}
			return v
		}

		for i := 0; i+4 <= len(ops); i += 4 {
			kind, a, b, c := ops[i], ops[i+1], ops[i+2], ops[i+3]
			now = now.Add(time.Duration(c) * 10 * time.Millisecond)
			switch kind % 7 {
			case 0:
				p.handleTraceEvent(traceEvent{Kind: traceEventAccept, PID: listener(a), RemoteIP: ips[int(b)%len(ips)], Timestamp: now})
			case 1:
				parent := pid(b)
				if b&0x80 != 0 {
					parent = listener(b)
				}
				p.handleTraceEvent(traceEvent{Kind: traceEventFork, PID: pid(a), ParentPID: parent, Timestamp: now})
			case 2:
				p.handleTraceEvent(traceEvent{Kind: traceEventExec, PID: pid(a), Comm: comms[int(b)%len(comms)], Timestamp: now})
			case 3:
				p.handleTraceEvent(traceEvent{Kind: traceEventTTYWrite, PID: pid(a), Bytes: uint32(b%2) * 32, Timestamp: now})
			case 4:
				p.handleTraceEvent(traceEvent{Kind: traceEventExit, PID: pid(a), Timestamp: now})
			case 5:
				p.HandleAuthEvent(authlog.AuthEvent{
					Type: authlog.EventAuthSuccess, PID: pid(a),
					User: users[int(b)%len(users)], RemoteIP: ips[int(c)%len(ips)], Timestamp: now,
				})
			case 6:
				p.cleanupExpired()
			}
		}

		// Every process exits, then the timeout passes.
		pids := make([]int32, 0, len(seen))
		for v := range seen {
			pids = append(pids, v)
		}
		slices.Sort(pids)
		for _, v := range pids {
			p.handleTraceEvent(traceEvent{Kind: traceEventExit, PID: v, Timestamp: now})
		}
		now = now.Add(timeout + time.Second)
		p.cleanupExpired()

		p.mu.Lock()
		state := map[string]int{
			"pendingAccepts":  len(p.pendingAccepts),
			"procToRoot":      len(p.procToRoot),
			"sessions":        len(p.sessions),
			"acceptedByPID":   len(p.acceptedByPID),
			"acceptedByTuple": len(p.acceptedByTuple),
		}
		p.mu.Unlock()
		for name, n := range state {
			if n != 0 {
				t.Errorf("%s still holds %d entries after every process exited and the timeout passed", name, n)
			}
		}

		counts := map[string]uint64{}
		families, err := reg.Gather()
		if err != nil {
			t.Fatalf("gather: %v", err)
		}
		for _, mf := range families {
			for _, m := range mf.GetMetric() {
				if h := m.GetHistogram(); h != nil {
					counts[mf.GetName()] += h.GetSampleCount()
				}
			}
		}
		usable := counts["ssh_accept_to_shell_usable_seconds"]
		for _, name := range []string{
			"ssh_accept_to_child_fork_seconds",
			"ssh_child_fork_to_shell_exec_seconds",
			"ssh_shell_exec_to_first_tty_output_seconds",
		} {
			if counts[name] != usable {
				t.Errorf("%s has %d observations, ssh_accept_to_shell_usable_seconds %d", name, counts[name], usable)
			}
		}
	})
}
