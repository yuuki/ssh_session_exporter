package collector

import (
	"context"
	"log/slog"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuuki/ssh_sesshon_exporter/authlog"
	"github.com/yuuki/ssh_sesshon_exporter/sessiontracker"
	"github.com/yuuki/ssh_sesshon_exporter/utmp"
)

var (
	sessionsActiveDesc = prometheus.NewDesc(
		"ssh_sessions_active",
		"Number of currently active SSH sessions.",
		[]string{"user", "remote_ip", "tty"}, nil,
	)
	scrapeSuccessDesc = prometheus.NewDesc(
		"ssh_exporter_scrape_success",
		"Whether the SSH exporter scrape was successful.",
		nil, nil,
	)
)

// SSHCollector implements prometheus.Collector for SSH session metrics.
type SSHCollector struct {
	utmpReader      utmp.Reader
	tracker         *sessiontracker.Tracker
	logger          *slog.Logger

	authFailures    *prometheus.CounterVec
	connections     *prometheus.CounterVec
	disconnections  *prometheus.CounterVec
	sessionDuration *prometheus.HistogramVec

	mu sync.Mutex
}

// New creates a new SSHCollector and registers counter/histogram metrics.
func New(
	reg prometheus.Registerer,
	utmpReader utmp.Reader,
	tracker *sessiontracker.Tracker,
	logger *slog.Logger,
) (*SSHCollector, error) {
	authFailures := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssh_auth_failures_total",
		Help: "Total number of SSH authentication failures.",
	}, []string{"user", "remote_ip", "method"})

	connections := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssh_connections_total",
		Help: "Total number of SSH connections established.",
	}, []string{"user", "remote_ip"})

	disconnections := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssh_disconnections_total",
		Help: "Total number of SSH disconnections.",
	}, []string{"user", "remote_ip"})

	sessionDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ssh_session_duration_seconds",
		Help:    "Distribution of SSH session durations in seconds.",
		Buckets: []float64{60, 300, 900, 1800, 3600, 7200, 14400, 28800, 86400},
	}, []string{"user"})

	c := &SSHCollector{
		utmpReader:      utmpReader,
		tracker:         tracker,
		logger:          logger,
		authFailures:    authFailures,
		connections:     connections,
		disconnections:  disconnections,
		sessionDuration: sessionDuration,
	}

	for _, col := range []prometheus.Collector{authFailures, connections, disconnections, sessionDuration, c} {
		if err := reg.Register(col); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// Describe implements prometheus.Collector.
func (c *SSHCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- sessionsActiveDesc
	ch <- scrapeSuccessDesc
}

// Collect implements prometheus.Collector. It reads utmp, detects session
// changes, and emits gauge metrics for active sessions.
func (c *SSHCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	sessions, err := c.utmpReader.ReadSessions()
	if err != nil {
		c.logger.Error("failed to read utmp", "error", err)
		ch <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, 0)
		return
	}

	// Detect session changes and update counters.
	delta := c.tracker.UpdateSessions(sessions)
	for _, ended := range delta.EndedSessions {
		c.sessionDuration.WithLabelValues(ended.User).Observe(ended.Duration.Seconds())
		c.disconnections.WithLabelValues(ended.User, ended.RemoteIP).Inc()
	}
	for _, newS := range delta.NewSessions {
		c.connections.WithLabelValues(newS.User, newS.RemoteIP).Inc()
	}

	// Emit active session gauges.
	for _, s := range sessions {
		ch <- prometheus.MustNewConstMetric(
			sessionsActiveDesc, prometheus.GaugeValue, 1,
			s.User, s.Host, s.TTY,
		)
	}

	ch <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, 1)
}

// Run processes auth log events and updates counter metrics.
// It blocks until the context is cancelled or the events channel is closed.
func (c *SSHCollector) Run(ctx context.Context, authEvents <-chan authlog.AuthEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-authEvents:
			if !ok {
				return
			}
			switch event.Type {
			case authlog.EventAuthFailure:
				c.authFailures.WithLabelValues(event.User, event.RemoteIP, event.Method).Inc()
			case authlog.EventAuthSuccess:
				// Connection counting is handled by utmp delta in Collect.
			case authlog.EventDisconnect:
				// Disconnection counting is handled by utmp delta in Collect.
			}
		}
	}
}
