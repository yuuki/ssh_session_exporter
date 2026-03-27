package collector

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuuki/ssh_session_exporter/authlog"
	"github.com/yuuki/ssh_session_exporter/sessiontracker"
	"github.com/yuuki/ssh_session_exporter/utmp"
)

const (
	shortSessionThreshold = 30 * time.Second
	// correlatorTTL bounds memory usage: entries from PIDs that never complete
	// auth (e.g., brute-force attempts) are evicted after this duration.
	correlatorTTL = 5 * time.Minute
)

var (
	sessionsActiveDesc = prometheus.NewDesc(
		"ssh_sessions_active",
		"Number of currently active SSH sessions.",
		[]string{"user", "remote_ip", "tty"}, nil,
	)
	sessionsCountDesc = prometheus.NewDesc(
		"ssh_sessions_count",
		"Number of currently active SSH sessions.",
		nil, nil,
	)
	scrapeSuccessDesc = prometheus.NewDesc(
		"ssh_exporter_scrape_success",
		"Whether the SSH exporter scrape was successful.",
		nil, nil,
	)
)

// SSHCollector implements prometheus.Collector for SSH session metrics.
type SSHCollector struct {
	utmpReader         utmp.Reader
	tracker            *sessiontracker.Tracker
	logger             *slog.Logger
	correlator         *pidCorrelator
	authFailures       *prometheus.CounterVec
	authSuccesses      *prometheus.CounterVec
	invalidUsers       *prometheus.CounterVec
	preauthDisconnects *prometheus.CounterVec
	connections        *prometheus.CounterVec
	disconnections     *prometheus.CounterVec
	sessionDuration    *prometheus.HistogramVec
	loginSetup         *prometheus.HistogramVec
	authAttempts       *prometheus.HistogramVec
	shortSessions      *prometheus.CounterVec
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

	authSuccesses := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssh_auth_success_total",
		Help: "Total number of successful SSH authentications.",
	}, []string{"user", "remote_ip", "method"})

	invalidUsers := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssh_invalid_user_attempts_total",
		Help: "Total number of SSH authentication attempts for invalid users.",
	}, []string{"user", "remote_ip"})

	preauthDisconnects := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssh_preauth_disconnects_total",
		Help: "Total number of SSH disconnections before authentication completed.",
	}, []string{"user", "remote_ip"})

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

	loginSetup := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ssh_login_setup_seconds",
		Help:    "Time from authentication success to session appearing in utmp.",
		Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30},
	}, []string{"user"})

	authAttempts := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ssh_auth_attempts_before_success",
		Help:    "Number of failed authentication attempts before a successful login.",
		Buckets: []float64{0, 1, 2, 3, 5, 10},
	}, []string{"user"})

	shortSessions := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssh_short_sessions_total",
		Help: "Total number of SSH sessions that ended within 30 seconds.",
	}, []string{"user", "remote_ip"})

	c := &SSHCollector{
		utmpReader:         utmpReader,
		tracker:            tracker,
		logger:             logger,
		correlator:         newPIDCorrelator(correlatorTTL),
		authFailures:       authFailures,
		authSuccesses:      authSuccesses,
		invalidUsers:       invalidUsers,
		preauthDisconnects: preauthDisconnects,
		connections:        connections,
		disconnections:     disconnections,
		sessionDuration:    sessionDuration,
		loginSetup:         loginSetup,
		authAttempts:       authAttempts,
		shortSessions:      shortSessions,
	}

	for _, col := range []prometheus.Collector{authFailures, authSuccesses, invalidUsers, preauthDisconnects, connections, disconnections, sessionDuration, loginSetup, authAttempts, shortSessions, c} {
		if err := reg.Register(col); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// Describe implements prometheus.Collector.
func (c *SSHCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- sessionsActiveDesc
	ch <- sessionsCountDesc
	ch <- scrapeSuccessDesc
}

// Collect reads utmp, detects session changes, and emits gauge metrics.
func (c *SSHCollector) Collect(ch chan<- prometheus.Metric) {
	sessions, err := c.utmpReader.ReadSessions()
	if err != nil {
		c.logger.Error("failed to read utmp", "error", err)
		ch <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, 0)
		return
	}

	delta := c.tracker.UpdateSessions(sessions)
	for _, ended := range delta.EndedSessions {
		c.sessionDuration.WithLabelValues(ended.User).Observe(ended.Duration.Seconds())
		c.disconnections.WithLabelValues(ended.User, ended.Host).Inc()
		if ended.Duration <= shortSessionThreshold {
			c.shortSessions.WithLabelValues(ended.User, ended.Host).Inc()
		}
	}
	for _, newS := range delta.NewSessions {
		c.connections.WithLabelValues(newS.User, newS.Host).Inc()
		if acceptTime, ok := c.correlator.ConsumeAccept(newS.PID); ok {
			setupDuration := newS.LoginTime.Sub(acceptTime)
			if setupDuration >= 0 {
				c.loginSetup.WithLabelValues(newS.User).Observe(setupDuration.Seconds())
			}
		} else {
			// Accept hasn't arrived yet; park session so Run() can resolve it later.
			c.correlator.RecordNewSession(newS.PID, newS.User, newS.LoginTime)
		}
	}

	for _, s := range sessions {
		ch <- prometheus.MustNewConstMetric(
			sessionsActiveDesc, prometheus.GaugeValue, 1,
			s.User, s.Host, s.TTY,
		)
	}

	ch <- prometheus.MustNewConstMetric(sessionsCountDesc, prometheus.GaugeValue, float64(len(sessions)))
	ch <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, 1)
}

// RunCleanup periodically removes stale PID correlation entries.
func (c *SSHCollector) RunCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.correlator.Cleanup()
		}
	}
}

// Run processes auth log events and updates the corresponding counters.
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
				c.correlator.RecordFailure(event.PID)
			case authlog.EventAuthSuccess:
				c.authSuccesses.WithLabelValues(event.User, event.RemoteIP, event.Method).Inc()
				failCount, setup := c.correlator.RecordAccept(event.PID, event.Timestamp)
				c.authAttempts.WithLabelValues(event.User).Observe(float64(failCount))
				if setup != nil {
					c.loginSetup.WithLabelValues(setup.User).Observe(setup.Duration.Seconds())
				}
			case authlog.EventInvalidUser:
				c.invalidUsers.WithLabelValues(event.User, event.RemoteIP).Inc()
			case authlog.EventPreauthDisconnect:
				c.preauthDisconnects.WithLabelValues(event.User, event.RemoteIP).Inc()
			}
		}
	}
}
