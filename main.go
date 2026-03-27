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

	"github.com/yuuki/ssh_sesshon_exporter/authlog"
	"github.com/yuuki/ssh_sesshon_exporter/collector"
	"github.com/yuuki/ssh_sesshon_exporter/sessiontracker"
	"github.com/yuuki/ssh_sesshon_exporter/utmp"
)

var (
	listenAddress = flag.String("web.listen-address", ":9842",
		"Address to listen on for web interface and telemetry.")
	metricsPath = flag.String("web.telemetry-path", "/metrics",
		"Path under which to expose metrics.")
	utmpPath = flag.String("utmp.path", "/var/run/utmp",
		"Path to the utmp file.")
	authLogPath = flag.String("auth-log.path", "/var/log/auth.log",
		"Path to the auth log file.")
)

func main() {
	flag.Parse()

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

	// Auth log watcher (optional — continue without it if unavailable).
	authWatcher := authlog.NewFileWatcher(*authLogPath, logger)
	if err := authWatcher.Start(ctx); err != nil {
		logger.Warn("failed to start auth log watcher, auth metrics will be unavailable",
			"path", *authLogPath, "error", err)
	} else {
		go sshCollector.Run(ctx, authWatcher.Events())
		logger.Info("auth log watcher started", "path", *authLogPath)
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

	authWatcher.Stop()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}
}
