//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/yuuki/ssh_session_exporter/authlog"
	"github.com/yuuki/ssh_session_exporter/collector"
	"github.com/yuuki/ssh_session_exporter/ebpf/sessionlatency"
	"github.com/yuuki/ssh_session_exporter/sessiontracker"
	"github.com/yuuki/ssh_session_exporter/utmp"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

const defaultAuthLogPath = "/var/log/auth.log"

var defaultAuthLogCandidates = []string{
	defaultAuthLogPath,
	"/var/log/secure",
}

var (
	listenAddress = flag.String("web.listen-address", ":9842",
		"Address to listen on for web interface and telemetry.")
	metricsPath = flag.String("web.telemetry-path", "/metrics",
		"Path under which to expose metrics.")
	utmpPath = flag.String("utmp.path", "/var/run/utmp",
		"Path to the utmp file.")
	authLogPath = flag.String("auth-log.path", defaultAuthLogPath,
		"Path to the auth log file.")
	ebpfShellUsableEnabled = flag.Bool("ebpf.shell-usable.enabled", false,
		"Enable eBPF-based SSH shell usable latency metrics.")
	ebpfShellUsableTimeout = flag.Duration("ebpf.shell-usable.timeout", 30*time.Second,
		"Timeout for eBPF shell usable latency correlation.")
	showVersion = flag.Bool("version", false, "Print version and exit.")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Data sources.
	utmpReader := utmp.NewFileReader(*utmpPath, logger)
	tracker := sessiontracker.New(logger)

	// Establish baseline: pre-existing sessions are not counted as new connections.
	if sessions, err := utmpReader.ReadSessions(); err != nil {
		logger.Warn("failed to read initial utmp baseline", "error", err)
	} else {
		tracker.Initialize(sessions)
	}

	// Prometheus registry.
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	sshCollector, err := collector.New(reg, utmpReader, tracker, logger)
	if err != nil {
		logger.Error("failed to create collector", "error", err)
		os.Exit(1)
	}

	var shellProbe *sessionlatency.Probe
	if *ebpfShellUsableEnabled {
		shellProbe, err = sessionlatency.Start(ctx, reg, logger, sessionlatency.Options{
			Timeout: *ebpfShellUsableTimeout,
		})
		if err != nil {
			logger.Warn("failed to start eBPF shell usable probe, metrics will be unavailable", "error", err)
		} else {
			logger.Info("eBPF shell usable probe started")
		}
	}

	// Correlator cleanup runs regardless of auth log availability,
	// because Collect() parks pending sessions even without auth log.
	go sshCollector.RunCleanup(ctx)

	// Auth log watcher (optional — continue without it if unavailable).
	resolvedAuthLogPath, ok := resolveAuthLogPath(*authLogPath, flagWasExplicitlySet("auth-log.path"), defaultAuthLogCandidates, authLogExists)
	var authWatcher *authlog.FileWatcher
	if !ok {
		logger.Info("auth log watcher disabled because no auth log file was found",
			"candidates", defaultAuthLogCandidates)
	} else {
		if resolvedAuthLogPath != *authLogPath {
			logger.Info("using fallback auth log path",
				"configured_path", *authLogPath,
				"path", resolvedAuthLogPath)
		}

		authWatcher = authlog.NewFileWatcher(resolvedAuthLogPath, logger)
		if err := authWatcher.Start(ctx); err != nil {
			logger.Warn("failed to start auth log watcher, auth metrics will be unavailable",
				"path", resolvedAuthLogPath, "error", err)
		} else {
			collectorEvents := make(chan authlog.AuthEvent, 256)
			go sshCollector.Run(ctx, collectorEvents)
			go fanOutAuthEvents(ctx, authWatcher.Events(), collectorEvents, shellProbe)
			logger.Info("auth log watcher started", "path", resolvedAuthLogPath)
		}
	}

	// HTTP server.
	mux := http.NewServeMux()
	mux.Handle(*metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><head><title>SSH Session Exporter</title></head>
<body><h1>SSH Session Exporter</h1>
<p><a href="%s">Metrics</a></p>
</body></html>`, *metricsPath)
	})

	server := &http.Server{
		Addr:    *listenAddress,
		Handler: mux,
	}

	go func() {
		logger.Info("starting SSH session exporter",
			"address", *listenAddress,
			"utmp", *utmpPath,
		)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if authWatcher != nil {
		authWatcher.Stop()
	}
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}
}

func fanOutAuthEvents(ctx context.Context, src <-chan authlog.AuthEvent, collectorEvents chan<- authlog.AuthEvent, shellProbe *sessionlatency.Probe) {
	defer close(collectorEvents)

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-src:
			if !ok {
				return
			}

			select {
			case collectorEvents <- event:
			case <-ctx.Done():
				return
			}
			if shellProbe != nil {
				shellProbe.HandleAuthEvent(event)
			}
		}
	}
}

func resolveAuthLogPath(configuredPath string, explicit bool, candidates []string, exists func(string) bool) (string, bool) {
	if explicit {
		return configuredPath, true
	}
	for _, candidate := range candidates {
		if exists(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func authLogExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return true
}

func flagWasExplicitlySet(name string) bool {
	explicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			explicit = true
		}
	})
	return explicit
}
