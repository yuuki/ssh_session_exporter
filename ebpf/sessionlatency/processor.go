package sessionlatency

import (
	"fmt"
	"log/slog"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuuki/ssh_session_exporter/authlog"
)

const defaultTimeout = 30 * time.Second

type Options struct {
	Timeout time.Duration
}

type traceEventKind uint8

const (
	traceEventAccept traceEventKind = iota + 1
	traceEventFork
	traceEventExec
	traceEventTTYWrite
	traceEventExit
)

type traceEvent struct {
	Kind       traceEventKind
	PID        int32
	ParentPID  int32
	UID        uint32
	Comm       string
	ParentComm string
	RemoteIP   string
	Bytes      uint32
	Timestamp  time.Time
}

type acceptEntry struct {
	remoteIP string
	ts       time.Time
}

type tupleKey struct {
	user     string
	remoteIP string
}

type acceptedAuth struct {
	user     string
	remoteIP string
	ts       time.Time
	expires  time.Time
}

type sessionState struct {
	rootPID         int32
	remoteIP        string
	user            string
	acceptTS        time.Time
	forkTS          time.Time
	shellExecTS     time.Time
	firstTTYWriteTS time.Time
	deadline        time.Time
	sawShellExec    bool
	sawTTYWrite     bool
	activePIDs      map[int32]struct{}
}

type processor struct {
	mu sync.Mutex

	logger      *slog.Logger
	timeout     time.Duration
	now         func() time.Time
	resolveUser func(uid uint32) (string, bool)

	pendingAccepts  map[int32][]acceptEntry
	procToRoot      map[int32]int32
	sessions        map[int32]*sessionState
	acceptedByPID   map[int32]acceptedAuth
	acceptedByTuple map[tupleKey][]acceptedAuth

	up                        prometheus.Gauge
	acceptToShellUsable       *prometheus.HistogramVec
	acceptToChildFork         *prometheus.HistogramVec
	childForkToShellExec      *prometheus.HistogramVec
	shellExecToFirstTTYOutput *prometheus.HistogramVec
	failures                  *prometheus.CounterVec
}

func newProcessor(reg prometheus.Registerer, logger *slog.Logger, opts Options) (*processor, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	p := &processor{
		logger:          logger,
		timeout:         timeout,
		now:             time.Now,
		resolveUser:     lookupUsername,
		pendingAccepts:  make(map[int32][]acceptEntry),
		procToRoot:      make(map[int32]int32),
		sessions:        make(map[int32]*sessionState),
		acceptedByPID:   make(map[int32]acceptedAuth),
		acceptedByTuple: make(map[tupleKey][]acceptedAuth),
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ssh_exporter_ebpf_shell_usable_up",
			Help: "Whether the eBPF shell usable latency probe is running.",
		}),
		acceptToShellUsable: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ssh_accept_to_shell_usable_seconds",
			Help:    "Time from SSH accept to first PTY output for interactive sessions.",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"user", "remote_ip"}),
		acceptToChildFork: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ssh_accept_to_child_fork_seconds",
			Help:    "Time from SSH accept to the initial session child fork.",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"user", "remote_ip"}),
		childForkToShellExec: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ssh_child_fork_to_shell_exec_seconds",
			Help:    "Time from the initial session child fork to shell exec.",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"user", "remote_ip"}),
		shellExecToFirstTTYOutput: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ssh_shell_exec_to_first_tty_output_seconds",
			Help:    "Time from shell exec to the first PTY output.",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"user", "remote_ip"}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ssh_shell_usable_failures_total",
			Help: "Total number of shell usable latency probe failures.",
		}, []string{"stage"}),
	}

	for _, collector := range []prometheus.Collector{
		p.up,
		p.acceptToShellUsable,
		p.acceptToChildFork,
		p.childForkToShellExec,
		p.shellExecToFirstTTYOutput,
		p.failures,
	} {
		if err := reg.Register(collector); err != nil {
			return nil, err
		}
	}
	p.up.Set(0)
	return p, nil
}

func (p *processor) setUp(up bool) {
	if up {
		p.up.Set(1)
		return
	}
	p.up.Set(0)
}

func (p *processor) HandleAuthEvent(event authlog.AuthEvent) {
	if event.Type != authlog.EventAuthSuccess {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	auth := acceptedAuth{
		user:     event.User,
		remoteIP: event.RemoteIP,
		ts:       event.Timestamp,
		expires:  p.now().Add(p.timeout),
	}

	if rootPID, ok := p.procToRoot[event.PID]; ok {
		p.attachAcceptedIdentity(rootPID, auth)
		return
	}

	p.acceptedByPID[event.PID] = auth
	key := tupleKey{user: event.User, remoteIP: event.RemoteIP}
	p.acceptedByTuple[key] = append(p.acceptedByTuple[key], auth)
}

func (p *processor) handleTraceEvent(event traceEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch event.Kind {
	case traceEventAccept:
		p.pendingAccepts[event.PID] = append(p.pendingAccepts[event.PID], acceptEntry{
			remoteIP: event.RemoteIP,
			ts:       event.Timestamp,
		})
	case traceEventFork:
		p.handleForkLocked(event)
	case traceEventExec:
		p.handleExecLocked(event)
	case traceEventTTYWrite:
		p.handleTTYWriteLocked(event)
	case traceEventExit:
		p.handleExitLocked(event)
	}
}

func (p *processor) cleanupExpired() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	for pid, queue := range p.pendingAccepts {
		kept := queue[:0]
		for _, accept := range queue {
			if now.Sub(accept.ts) > p.timeout {
				p.failures.WithLabelValues("accept_orphaned").Inc()
				continue
			}
			kept = append(kept, accept)
		}
		if len(kept) == 0 {
			delete(p.pendingAccepts, pid)
		} else {
			p.pendingAccepts[pid] = kept
		}
	}

	for pid, auth := range p.acceptedByPID {
		if now.After(auth.expires) {
			delete(p.acceptedByPID, pid)
		}
	}

	for key, queue := range p.acceptedByTuple {
		kept := queue[:0]
		for _, auth := range queue {
			if now.After(auth.expires) {
				continue
			}
			kept = append(kept, auth)
		}
		if len(kept) == 0 {
			delete(p.acceptedByTuple, key)
		} else {
			p.acceptedByTuple[key] = kept
		}
	}

	for rootPID, session := range p.sessions {
		if now.Before(session.deadline) || session.sawTTYWrite {
			continue
		}
		if session.sawShellExec {
			p.failures.WithLabelValues("tty_write_timeout").Inc()
		} else {
			p.failures.WithLabelValues("shell_exec_missing").Inc()
		}
		p.deleteSessionLocked(rootPID)
	}
}

func (p *processor) handleForkLocked(event traceEvent) {
	if rootPID, ok := p.procToRoot[event.ParentPID]; ok {
		p.procToRoot[event.PID] = rootPID
		if session, exists := p.sessions[rootPID]; exists {
			session.activePIDs[event.PID] = struct{}{}
		}
		p.attachAcceptedIdentityFromPID(rootPID, event.PID)
		return
	}

	if event.ParentComm != "sshd" || event.Comm != "sshd" {
		return
	}

	queue := p.pendingAccepts[event.ParentPID]
	if len(queue) == 0 {
		p.failures.WithLabelValues("fork_unmatched").Inc()
		return
	}
	accept := queue[0]
	if len(queue) == 1 {
		delete(p.pendingAccepts, event.ParentPID)
	} else {
		p.pendingAccepts[event.ParentPID] = queue[1:]
	}

	session := &sessionState{
		rootPID:    rootPIDFromEvent(event),
		remoteIP:   accept.remoteIP,
		acceptTS:   accept.ts,
		forkTS:     event.Timestamp,
		deadline:   accept.ts.Add(p.timeout),
		activePIDs: map[int32]struct{}{event.PID: {}},
	}
	p.sessions[session.rootPID] = session
	p.procToRoot[event.PID] = session.rootPID
	p.attachAcceptedIdentityFromPID(session.rootPID, event.PID)
}

func rootPIDFromEvent(event traceEvent) int32 {
	return event.PID
}

func (p *processor) handleExecLocked(event traceEvent) {
	rootPID, ok := p.procToRoot[event.PID]
	if !ok {
		return
	}
	session := p.sessions[rootPID]
	if session == nil || !looksLikeShell(event.Comm) {
		return
	}
	if !session.sawShellExec {
		session.sawShellExec = true
		session.shellExecTS = event.Timestamp
	}
	if session.user == "" {
		if userName, ok := p.resolveUser(event.UID); ok {
			session.user = userName
		}
	}
	p.attachAcceptedIdentityFromPID(rootPID, event.PID)
}

func (p *processor) handleTTYWriteLocked(event traceEvent) {
	rootPID, ok := p.procToRoot[event.PID]
	if !ok {
		return
	}
	session := p.sessions[rootPID]
	if session == nil || session.sawTTYWrite || event.Bytes == 0 {
		return
	}
	if session.user == "" {
		if userName, ok := p.resolveUser(event.UID); ok {
			session.user = userName
		}
	}
	if !session.sawShellExec {
		p.failures.WithLabelValues("shell_exec_missing").Inc()
		p.deleteSessionLocked(rootPID)
		return
	}

	if session.user != "" {
		p.attachAcceptedIdentityFromTuple(rootPID)
	}
	if session.user == "" {
		p.failures.WithLabelValues("identity_unmatched").Inc()
		p.deleteSessionLocked(rootPID)
		return
	}

	session.sawTTYWrite = true
	session.firstTTYWriteTS = event.Timestamp
	labels := []string{session.user, session.remoteIP}
	p.acceptToShellUsable.WithLabelValues(labels...).Observe(event.Timestamp.Sub(session.acceptTS).Seconds())
	p.acceptToChildFork.WithLabelValues(labels...).Observe(session.forkTS.Sub(session.acceptTS).Seconds())
	p.childForkToShellExec.WithLabelValues(labels...).Observe(session.shellExecTS.Sub(session.forkTS).Seconds())
	p.shellExecToFirstTTYOutput.WithLabelValues(labels...).Observe(event.Timestamp.Sub(session.shellExecTS).Seconds())
	p.deleteSessionLocked(rootPID)
}

func (p *processor) handleExitLocked(event traceEvent) {
	rootPID, ok := p.procToRoot[event.PID]
	if !ok {
		return
	}
	session := p.sessions[rootPID]
	if session == nil {
		delete(p.procToRoot, event.PID)
		return
	}

	delete(session.activePIDs, event.PID)
	delete(p.procToRoot, event.PID)
	if len(session.activePIDs) > 0 {
		return
	}
	if session.sawTTYWrite {
		p.deleteSessionLocked(rootPID)
		return
	}
	if session.sawShellExec {
		p.failures.WithLabelValues("exited_before_usable").Inc()
	}
	p.deleteSessionLocked(rootPID)
}

func (p *processor) attachAcceptedIdentityFromPID(rootPID, pid int32) {
	auth, ok := p.acceptedByPID[pid]
	if !ok {
		return
	}
	if p.attachAcceptedIdentity(rootPID, auth) {
		delete(p.acceptedByPID, pid)
	}
}

func (p *processor) attachAcceptedIdentity(rootPID int32, auth acceptedAuth) bool {
	session := p.sessions[rootPID]
	if session == nil {
		return false
	}
	if session.remoteIP != "" && auth.remoteIP != "" && session.remoteIP != auth.remoteIP {
		return false
	}
	session.user = auth.user
	if session.remoteIP == "" {
		session.remoteIP = auth.remoteIP
	}
	return true
}

func (p *processor) attachAcceptedIdentityFromTuple(rootPID int32) {
	session := p.sessions[rootPID]
	if session == nil || session.user == "" || session.remoteIP == "" {
		return
	}
	key := tupleKey{user: session.user, remoteIP: session.remoteIP}
	queue := p.acceptedByTuple[key]
	if len(queue) == 0 {
		return
	}
	auth := queue[0]
	if len(queue) == 1 {
		delete(p.acceptedByTuple, key)
	} else {
		p.acceptedByTuple[key] = queue[1:]
	}
	p.attachAcceptedIdentity(rootPID, auth)
}

func (p *processor) deleteSessionLocked(rootPID int32) {
	session := p.sessions[rootPID]
	if session == nil {
		return
	}
	for pid := range session.activePIDs {
		delete(p.procToRoot, pid)
	}
	delete(p.sessions, rootPID)
}

func looksLikeShell(comm string) bool {
	comm = strings.TrimPrefix(strings.TrimSpace(comm), "-")
	switch comm {
	case "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh":
		return true
	default:
		return false
	}
}

func lookupUsername(uid uint32) (string, bool) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", false
	}
	if u.Username == "" {
		return "", false
	}
	return u.Username, true
}

func (e traceEvent) String() string {
	return fmt.Sprintf("kind=%d pid=%d ppid=%d comm=%q parent_comm=%q remote_ip=%q", e.Kind, e.PID, e.ParentPID, e.Comm, e.ParentComm, e.RemoteIP)
}
