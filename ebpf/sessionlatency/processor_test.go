package sessionlatency

import (
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/yuuki/ssh_session_exporter/authlog"
)

func TestProcessorRecordsHistogramsWithPIDIdentityMatch(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Unix(1_700_000_000, 0)

	p, err := newProcessor(reg, slog.Default(), Options{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}
	p.now = func() time.Time { return now }
	p.resolveUser = func(uid uint32) (string, bool) {
		switch uid {
		case 1001:
			return "alice", true
		case 1002:
			return "bob", true
		default:
			return "", false
		}
	}

	p.handleTraceEvent(traceEvent{Kind: traceEventAccept, PID: 10, RemoteIP: "192.0.2.10", Timestamp: now})
	p.handleTraceEvent(traceEvent{Kind: traceEventAccept, PID: 10, RemoteIP: "192.0.2.11", Timestamp: now.Add(50 * time.Millisecond)})

	p.handleTraceEvent(traceEvent{Kind: traceEventFork, PID: 101, ParentPID: 10, ParentComm: "sshd", Comm: "sshd", Timestamp: now.Add(100 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventFork, PID: 102, ParentPID: 10, ParentComm: "sshd", Comm: "sshd", Timestamp: now.Add(150 * time.Millisecond)})

	p.HandleAuthEvent(authlog.AuthEvent{Type: authlog.EventAuthSuccess, PID: 101, User: "alice", RemoteIP: "192.0.2.10", Timestamp: now.Add(200 * time.Millisecond)})
	p.HandleAuthEvent(authlog.AuthEvent{Type: authlog.EventAuthSuccess, PID: 102, User: "bob", RemoteIP: "192.0.2.11", Timestamp: now.Add(220 * time.Millisecond)})

	p.handleTraceEvent(traceEvent{Kind: traceEventFork, PID: 201, ParentPID: 101, ParentComm: "sshd", Comm: "sshd", Timestamp: now.Add(300 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventExec, PID: 201, UID: 1001, Comm: "bash", Timestamp: now.Add(350 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventTTYWrite, PID: 201, UID: 1001, Bytes: 32, Timestamp: now.Add(700 * time.Millisecond)})

	p.handleTraceEvent(traceEvent{Kind: traceEventFork, PID: 202, ParentPID: 102, ParentComm: "sshd", Comm: "sshd", Timestamp: now.Add(400 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventExec, PID: 202, UID: 1002, Comm: "zsh", Timestamp: now.Add(450 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventTTYWrite, PID: 202, UID: 1002, Bytes: 32, Timestamp: now.Add(900 * time.Millisecond)})

	assertHistogramCount(t, reg, "ssh_accept_to_shell_usable_seconds", map[string]string{"user": "alice", "remote_ip": "192.0.2.10"}, 1)
	assertHistogramCount(t, reg, "ssh_accept_to_shell_usable_seconds", map[string]string{"user": "bob", "remote_ip": "192.0.2.11"}, 1)
	assertHistogramCount(t, reg, "ssh_accept_to_child_fork_seconds", map[string]string{"user": "alice", "remote_ip": "192.0.2.10"}, 1)
	assertHistogramCount(t, reg, "ssh_child_fork_to_shell_exec_seconds", map[string]string{"user": "alice", "remote_ip": "192.0.2.10"}, 1)
	assertHistogramCount(t, reg, "ssh_shell_exec_to_first_tty_output_seconds", map[string]string{"user": "alice", "remote_ip": "192.0.2.10"}, 1)
}

func TestProcessorRecordsHistogramsWithTupleFallback(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Unix(1_700_000_100, 0)

	p, err := newProcessor(reg, slog.Default(), Options{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}
	p.now = func() time.Time { return now }
	p.resolveUser = func(uid uint32) (string, bool) {
		if uid == 1001 {
			return "alice", true
		}
		return "", false
	}

	p.handleTraceEvent(traceEvent{Kind: traceEventAccept, PID: 10, RemoteIP: "198.51.100.7", Timestamp: now})
	p.handleTraceEvent(traceEvent{Kind: traceEventFork, PID: 101, ParentPID: 10, ParentComm: "sshd", Comm: "sshd", Timestamp: now.Add(100 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventFork, PID: 201, ParentPID: 101, ParentComm: "sshd", Comm: "sshd", Timestamp: now.Add(200 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventExec, PID: 201, UID: 1001, Comm: "bash", Timestamp: now.Add(250 * time.Millisecond)})

	p.HandleAuthEvent(authlog.AuthEvent{
		Type:      authlog.EventAuthSuccess,
		PID:       9999,
		User:      "alice",
		RemoteIP:  "198.51.100.7",
		Timestamp: now.Add(300 * time.Millisecond),
	})

	p.handleTraceEvent(traceEvent{Kind: traceEventTTYWrite, PID: 201, UID: 1001, Bytes: 32, Timestamp: now.Add(500 * time.Millisecond)})

	assertHistogramCount(t, reg, "ssh_accept_to_shell_usable_seconds", map[string]string{"user": "alice", "remote_ip": "198.51.100.7"}, 1)
	assertCounterValue(t, reg, "ssh_shell_usable_failures_total", map[string]string{"stage": "identity_unmatched"}, 0)
}

func TestProcessorCreatesRootFromAcceptedAuthWhenForkCorrelationIsMissing(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Unix(1_700_000_150, 0)

	p, err := newProcessor(reg, slog.Default(), Options{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}
	p.now = func() time.Time { return now }
	p.resolveUser = func(uid uint32) (string, bool) {
		if uid == 1001 {
			return "alice", true
		}
		return "", false
	}

	p.handleTraceEvent(traceEvent{Kind: traceEventAccept, PID: 10, RemoteIP: "198.51.100.9", Timestamp: now})
	p.HandleAuthEvent(authlog.AuthEvent{
		Type:      authlog.EventAuthSuccess,
		PID:       5001,
		User:      "alice",
		RemoteIP:  "198.51.100.9",
		Timestamp: now.Add(100 * time.Millisecond),
	})
	p.handleTraceEvent(traceEvent{Kind: traceEventExec, PID: 5001, UID: 1001, Comm: "bash", Timestamp: now.Add(200 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventTTYWrite, PID: 5001, UID: 1001, Bytes: 32, Timestamp: now.Add(400 * time.Millisecond)})

	assertHistogramCount(t, reg, "ssh_accept_to_shell_usable_seconds", map[string]string{"user": "alice", "remote_ip": "198.51.100.9"}, 1)
}

func TestProcessorTracksTimeoutAndExitFailurePaths(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Unix(1_700_000_200, 0)

	p, err := newProcessor(reg, slog.Default(), Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}
	p.now = func() time.Time { return now }
	p.resolveUser = func(uid uint32) (string, bool) { return "alice", true }

	p.handleTraceEvent(traceEvent{Kind: traceEventAccept, PID: 10, RemoteIP: "203.0.113.1", Timestamp: now})
	p.handleTraceEvent(traceEvent{Kind: traceEventFork, PID: 101, ParentPID: 10, ParentComm: "sshd", Comm: "sshd", Timestamp: now.Add(100 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventExec, PID: 101, UID: 1001, Comm: "bash", Timestamp: now.Add(200 * time.Millisecond)})
	now = now.Add(6 * time.Second)
	p.cleanupExpired()

	p.handleTraceEvent(traceEvent{Kind: traceEventAccept, PID: 10, RemoteIP: "203.0.113.2", Timestamp: now})
	p.handleTraceEvent(traceEvent{Kind: traceEventFork, PID: 102, ParentPID: 10, ParentComm: "sshd", Comm: "sshd", Timestamp: now.Add(100 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventExec, PID: 102, UID: 1001, Comm: "bash", Timestamp: now.Add(200 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventExit, PID: 102, Timestamp: now.Add(300 * time.Millisecond)})

	p.handleTraceEvent(traceEvent{Kind: traceEventAccept, PID: 10, RemoteIP: "203.0.113.3", Timestamp: now.Add(1 * time.Second)})
	p.handleTraceEvent(traceEvent{Kind: traceEventFork, PID: 103, ParentPID: 10, ParentComm: "sshd", Comm: "sshd", Timestamp: now.Add(1100 * time.Millisecond)})
	p.handleTraceEvent(traceEvent{Kind: traceEventExit, PID: 103, Timestamp: now.Add(1200 * time.Millisecond)})

	assertCounterValue(t, reg, "ssh_shell_usable_failures_total", map[string]string{"stage": "tty_write_timeout"}, 1)
	assertCounterValue(t, reg, "ssh_shell_usable_failures_total", map[string]string{"stage": "exited_before_usable"}, 1)
	assertCounterValue(t, reg, "ssh_shell_usable_failures_total", map[string]string{"stage": "identity_unmatched"}, 0)
	assertHistogramCount(t, reg, "ssh_accept_to_shell_usable_seconds", map[string]string{"user": "alice", "remote_ip": "203.0.113.3"}, 0)
}

func TestProcessorCleanupExpiredDropsOnlyStaleState(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	now := time.Unix(1_700_000_300, 0)
	const timeout = 5 * time.Second

	p, err := newProcessor(reg, slog.Default(), Options{Timeout: timeout})
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}
	p.now = func() time.Time { return now }

	// Accepts expire strictly after the timeout; auths strictly after expires;
	// sessions once the deadline is reached.
	p.pendingAccepts[10] = []acceptEntry{
		{remoteIP: "192.0.2.1", ts: now.Add(-timeout - time.Second)},
		{remoteIP: "192.0.2.2", ts: now.Add(-timeout)},
		{remoteIP: "192.0.2.3", ts: now.Add(-time.Second)},
	}
	p.pendingAccepts[11] = []acceptEntry{{remoteIP: "192.0.2.4", ts: now.Add(-2 * timeout)}}

	p.acceptedByPID[100] = acceptedAuth{user: "stale", expires: now.Add(-time.Nanosecond)}
	p.acceptedByPID[101] = acceptedAuth{user: "boundary", expires: now}
	p.acceptedByPID[102] = acceptedAuth{user: "fresh", expires: now.Add(time.Second)}

	mixed := tupleKey{user: "alice", remoteIP: "192.0.2.10"}
	expired := tupleKey{user: "bob", remoteIP: "192.0.2.11"}
	p.acceptedByTuple[mixed] = []acceptedAuth{
		{user: "alice", remoteIP: "192.0.2.10", expires: now.Add(-time.Second)},
		{user: "alice", remoteIP: "192.0.2.10", expires: now},
		{user: "alice", remoteIP: "192.0.2.10", expires: now.Add(time.Second)},
	}
	p.acceptedByTuple[expired] = []acceptedAuth{{user: "bob", remoteIP: "192.0.2.11", expires: now.Add(-time.Second)}}

	addSession := func(rootPID int32, deadline time.Time, sawShellExec, sawTTYWrite bool) {
		p.sessions[rootPID] = &sessionState{
			rootPID:      rootPID,
			deadline:     deadline,
			sawShellExec: sawShellExec,
			sawTTYWrite:  sawTTYWrite,
			activePIDs:   map[int32]struct{}{rootPID: {}, rootPID + 1: {}},
		}
		p.procToRoot[rootPID] = rootPID
		p.procToRoot[rootPID+1] = rootPID
	}
	addSession(200, now.Add(-time.Second), true, false) // shell ran, never wrote
	addSession(210, now.Add(-time.Second), false, false)
	addSession(220, now, false, false)
	addSession(230, now.Add(time.Second), false, false)
	addSession(240, now.Add(-time.Second), true, true)

	p.cleanupExpired()

	assertCounterValue(t, reg, "ssh_shell_usable_failures_total", map[string]string{"stage": "accept_orphaned"}, 2)
	assertCounterValue(t, reg, "ssh_shell_usable_failures_total", map[string]string{"stage": "tty_write_timeout"}, 1)
	assertCounterValue(t, reg, "ssh_shell_usable_failures_total", map[string]string{"stage": "shell_exec_missing"}, 2)

	wantAccepts := map[int32][]acceptEntry{10: {
		{remoteIP: "192.0.2.2", ts: now.Add(-timeout)},
		{remoteIP: "192.0.2.3", ts: now.Add(-time.Second)},
	}}
	if !reflect.DeepEqual(p.pendingAccepts, wantAccepts) {
		t.Errorf("pendingAccepts = %+v, want %+v", p.pendingAccepts, wantAccepts)
	}
	wantByPID := map[int32]acceptedAuth{
		101: {user: "boundary", expires: now},
		102: {user: "fresh", expires: now.Add(time.Second)},
	}
	if !reflect.DeepEqual(p.acceptedByPID, wantByPID) {
		t.Errorf("acceptedByPID = %+v, want %+v", p.acceptedByPID, wantByPID)
	}
	wantByTuple := map[tupleKey][]acceptedAuth{mixed: {
		{user: "alice", remoteIP: "192.0.2.10", expires: now},
		{user: "alice", remoteIP: "192.0.2.10", expires: now.Add(time.Second)},
	}}
	if !reflect.DeepEqual(p.acceptedByTuple, wantByTuple) {
		t.Errorf("acceptedByTuple = %+v, want %+v", p.acceptedByTuple, wantByTuple)
	}
	if len(p.sessions) != 2 || p.sessions[230] == nil || p.sessions[240] == nil {
		t.Errorf("expected only sessions 230 and 240 to survive, got %+v", p.sessions)
	}
	wantProcToRoot := map[int32]int32{230: 230, 231: 230, 240: 240, 241: 240}
	if !reflect.DeepEqual(p.procToRoot, wantProcToRoot) {
		t.Errorf("procToRoot = %v, want %v", p.procToRoot, wantProcToRoot)
	}
}

func assertHistogramCount(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string, want uint64) {
	t.Helper()
	mf := findMetricFamily(t, reg, name)
	if mf == nil {
		if want == 0 {
			return
		}
		t.Fatalf("metric family %q not found", name)
	}
	for _, metric := range mf.Metric {
		if metricLabels(metric) == labelKey(labels) {
			if got := metric.GetHistogram().GetSampleCount(); got != want {
				t.Fatalf("%s labels=%v sample_count=%d want=%d", name, labels, got, want)
			}
			return
		}
	}
	if want == 0 {
		return
	}
	t.Fatalf("%s labels=%v not found", name, labels)
}

func assertCounterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string, want float64) {
	t.Helper()
	mf := findMetricFamily(t, reg, name)
	if mf == nil {
		if want == 0 {
			return
		}
		t.Fatalf("metric family %q not found", name)
	}
	for _, metric := range mf.Metric {
		if metricLabels(metric) == labelKey(labels) {
			if got := metric.GetCounter().GetValue(); got != want {
				t.Fatalf("%s labels=%v value=%v want=%v", name, labels, got, want)
			}
			return
		}
	}
	if want == 0 {
		return
	}
	t.Fatalf("%s labels=%v not found", name, labels)
}

func findMetricFamily(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

func metricLabels(metric *dto.Metric) string {
	labels := make(map[string]string, len(metric.Label))
	for _, label := range metric.Label {
		labels[label.GetName()] = label.GetValue()
	}
	return labelKey(labels)
}

func labelKey(labels map[string]string) string {
	return labels["remote_ip"] + "\x00" + labels["stage"] + "\x00" + labels["user"]
}
