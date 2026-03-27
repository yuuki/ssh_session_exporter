//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	baseURL    string
	composeDir string
)

func TestMain(m *testing.M) {
	port := os.Getenv("E2E_PORT")
	if port == "" {
		port = "9842"
	}
	baseURL = fmt.Sprintf("http://localhost:%s", port)

	// Determine compose file directory (same directory as this test file).
	// When running `go test ./e2e/`, the working directory is the e2e/ dir.
	composeDir = "."
	if _, err := os.Stat("docker-compose.e2e.yml"); err != nil {
		// Fallback: try from project root.
		composeDir = "e2e"
	}

	// Build and start containers.
	if err := compose("build"); err != nil {
		fmt.Fprintf(os.Stderr, "docker compose build failed: %v\n", err)
		os.Exit(1)
	}
	if err := compose("up", "-d", "--wait"); err != nil {
		fmt.Fprintf(os.Stderr, "docker compose up failed: %v\n", err)
		compose("down", "-v")
		os.Exit(1)
	}

	// Wait for the exporter to be ready.
	if err := waitForReady(30 * time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "exporter not ready: %v\n", err)
		compose("logs", "exporter")
		compose("down", "-v")
		os.Exit(1)
	}

	code := m.Run()

	compose("down", "-v")
	os.Exit(code)
}

func compose(args ...string) error {
	fullArgs := append([]string{"-f", composeDir + "/docker-compose.e2e.yml"}, args...)
	cmd := exec.Command("docker", append([]string{"compose"}, fullArgs...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func composeExec(args ...string) (string, error) {
	fullArgs := append([]string{
		"compose", "-f", composeDir + "/docker-compose.e2e.yml",
		"exec", "-T", "exporter",
	}, args...)
	cmd := exec.Command("docker", fullArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func waitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/metrics")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s/metrics", baseURL)
}

// --- Test data helpers ---

type sessionSpec struct {
	User  string `json:"user"`
	TTY   string `json:"tty"`
	Host  string `json:"host"`
	PID   int32  `json:"pid"`
	TvSec int32  `json:"tv_sec"`
}

func composeExecStdin(stdin io.Reader, args ...string) (string, error) {
	fullArgs := append([]string{
		"compose", "-f", composeDir + "/docker-compose.e2e.yml",
		"exec", "-T", "exporter",
	}, args...)
	cmd := exec.Command("docker", fullArgs...)
	cmd.Stdin = stdin
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func writeUtmpRecords(t *testing.T, records []sessionSpec) {
	t.Helper()
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal records: %v", err)
	}

	out, err := composeExecStdin(bytes.NewReader(data), "utmpwriter", "--path=/data/utmp", "--action=write")
	if err != nil {
		t.Fatalf("writeUtmpRecords: %v\n%s", err, out)
	}
}

func clearUtmp(t *testing.T) {
	t.Helper()
	out, err := composeExec("utmpwriter", "--path=/data/utmp", "--action=clear")
	if err != nil {
		t.Fatalf("clearUtmp: %v\n%s", err, out)
	}
}

func appendAuthLog(t *testing.T, line string) {
	t.Helper()
	escaped := strings.ReplaceAll(line, "'", "'\\''")
	out, err := composeExec("bash", "-c", fmt.Sprintf("echo '%s' >> /data/auth.log", escaped))
	if err != nil {
		t.Fatalf("appendAuthLog: %v\n%s", err, out)
	}
}

func scrapeMetrics(t *testing.T) string {
	t.Helper()
	resp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	return string(body)
}

// scrapeMetricsRetry scrapes metrics and retries until the condition is met.
func scrapeMetricsRetry(t *testing.T, check func(string) bool, retries int) string {
	t.Helper()
	for i := 0; i < retries; i++ {
		body := scrapeMetrics(t)
		if check(body) {
			return body
		}
		time.Sleep(500 * time.Millisecond)
	}
	// Return last attempt for assertion failure messages.
	return scrapeMetrics(t)
}

// --- Metric assertion helpers ---

func findMetricValue(body, name string, labels map[string]string) (float64, bool) {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !strings.HasPrefix(line, name) {
			continue
		}
		rest := line[len(name):]
		if len(rest) == 0 {
			continue
		}
		// For no-label metrics: expect "name <value>" (space after name).
		if len(labels) == 0 {
			if rest[0] != ' ' {
				continue
			}
		} else {
			// For labeled metrics: expect "name{...} <value>".
			if rest[0] != '{' {
				continue
			}
			allMatch := true
			for k, v := range labels {
				needle := fmt.Sprintf(`%s="%s"`, k, v)
				if !strings.Contains(line, needle) {
					allMatch = false
					break
				}
			}
			if !allMatch {
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		return val, true
	}
	return 0, false
}

func findMetricExists(body, name string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name) {
			rest := line[len(name):]
			if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '{') {
				return true
			}
		}
	}
	return false
}

func assertMetricValue(t *testing.T, body, name string, expected float64, labels map[string]string) {
	t.Helper()
	val, found := findMetricValue(body, name, labels)
	if !found {
		t.Errorf("metric %s%v not found in output:\n%s", name, labels, truncate(body, 2000))
		return
	}
	if val != expected {
		t.Errorf("metric %s%v: got %v, want %v", name, labels, val, expected)
	}
}

func assertMetricGE(t *testing.T, body, name string, minVal float64, labels map[string]string) {
	t.Helper()
	val, found := findMetricValue(body, name, labels)
	if !found {
		t.Errorf("metric %s%v not found in output:\n%s", name, labels, truncate(body, 2000))
		return
	}
	if val < minVal {
		t.Errorf("metric %s%v: got %v, want >= %v", name, labels, val, minVal)
	}
}

func assertMetricAbsent(t *testing.T, body, name string) {
	t.Helper()
	if findMetricExists(body, name) {
		t.Errorf("metric %s should be absent but was found", name)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n... (truncated)"
}

// --- E2E test scenarios ---

// triggerAndScrape performs two scrapes: the first triggers SSHCollector.Collect()
// which updates CounterVec/HistogramVec as a side-effect, the second captures
// stable counter values (avoids gather-ordering race between SSHCollector and
// separately-registered CounterVec/HistogramVec).
func triggerAndScrape(t *testing.T) string {
	t.Helper()
	scrapeMetrics(t) // trigger: SSHCollector updates counters
	return scrapeMetrics(t) // capture: CounterVec reports updated values
}

func TestE2E(t *testing.T) {
	now := int32(time.Now().Unix())

	t.Run("Baseline_NoSessions", func(t *testing.T) {
		body := scrapeMetrics(t)

		assertMetricValue(t, body, "ssh_sessions_count", 0, nil)
		assertMetricValue(t, body, "ssh_exporter_scrape_success", 1, nil)
		assertMetricAbsent(t, body, "ssh_sessions_active")
	})

	t.Run("NewSession_Alice", func(t *testing.T) {
		writeUtmpRecords(t, []sessionSpec{
			{User: "alice", TTY: "pts/0", Host: "192.168.1.10", PID: 1001, TvSec: now},
		})

		body := triggerAndScrape(t)

		assertMetricValue(t, body, "ssh_sessions_count", 1, nil)
		assertMetricValue(t, body, "ssh_sessions_active", 1, map[string]string{
			"user": "alice", "remote_ip": "192.168.1.10", "tty": "pts/0",
		})
		assertMetricValue(t, body, "ssh_connections_total", 1, map[string]string{
			"user": "alice", "remote_ip": "192.168.1.10",
		})
	})

	t.Run("MultipleUsers", func(t *testing.T) {
		writeUtmpRecords(t, []sessionSpec{
			{User: "alice", TTY: "pts/0", Host: "192.168.1.10", PID: 1001, TvSec: now},
			{User: "bob", TTY: "pts/1", Host: "10.0.0.5", PID: 1002, TvSec: now},
		})

		body := triggerAndScrape(t)

		assertMetricValue(t, body, "ssh_sessions_count", 2, nil)
		assertMetricValue(t, body, "ssh_sessions_active", 1, map[string]string{
			"user": "alice", "remote_ip": "192.168.1.10", "tty": "pts/0",
		})
		assertMetricValue(t, body, "ssh_sessions_active", 1, map[string]string{
			"user": "bob", "remote_ip": "10.0.0.5", "tty": "pts/1",
		})
		assertMetricValue(t, body, "ssh_connections_total", 1, map[string]string{
			"user": "bob", "remote_ip": "10.0.0.5",
		})
	})

	t.Run("SessionEnds", func(t *testing.T) {
		clearUtmp(t)

		body := triggerAndScrape(t)

		assertMetricValue(t, body, "ssh_sessions_count", 0, nil)
		assertMetricAbsent(t, body, "ssh_sessions_active")
		assertMetricGE(t, body, "ssh_disconnections_total", 1, map[string]string{
			"user": "alice", "remote_ip": "192.168.1.10",
		})
		assertMetricGE(t, body, "ssh_disconnections_total", 1, map[string]string{
			"user": "bob", "remote_ip": "10.0.0.5",
		})
		assertMetricGE(t, body, "ssh_session_duration_seconds_count", 1, map[string]string{
			"user": "alice",
		})
		assertMetricGE(t, body, "ssh_session_duration_seconds_count", 1, map[string]string{
			"user": "bob",
		})
	})

	t.Run("AuthFailure", func(t *testing.T) {
		appendAuthLog(t, "Mar 27 12:00:00 server sshd[9999]: Failed password for baduser from 10.0.0.99 port 22 ssh2")

		// Auth log tailing needs a moment to pick up the new line.
		body := scrapeMetricsRetry(t, func(b string) bool {
			_, found := findMetricValue(b, "ssh_auth_failures_total", map[string]string{
				"user": "baduser", "remote_ip": "10.0.0.99", "method": "password",
			})
			return found
		}, 6)

		assertMetricValue(t, body, "ssh_auth_failures_total", 1, map[string]string{
			"user": "baduser", "remote_ip": "10.0.0.99", "method": "password",
		})
	})

	t.Run("AuthSuccess", func(t *testing.T) {
		appendAuthLog(t, "Mar 27 12:01:00 server sshd[5001]: Accepted publickey for alice from 192.168.1.10 port 22 ssh2")

		body := scrapeMetricsRetry(t, func(b string) bool {
			_, found := findMetricValue(b, "ssh_auth_success_total", map[string]string{
				"user": "alice", "remote_ip": "192.168.1.10", "method": "publickey",
			})
			return found
		}, 6)

		assertMetricValue(t, body, "ssh_auth_success_total", 1, map[string]string{
			"user": "alice", "remote_ip": "192.168.1.10", "method": "publickey",
		})
	})

	t.Run("InvalidUser", func(t *testing.T) {
		appendAuthLog(t, "Mar 27 12:02:00 server sshd[5002]: Invalid user hacker from 10.0.0.99 port 22")

		body := scrapeMetricsRetry(t, func(b string) bool {
			_, found := findMetricValue(b, "ssh_invalid_user_attempts_total", map[string]string{
				"user": "hacker", "remote_ip": "10.0.0.99",
			})
			return found
		}, 6)

		assertMetricValue(t, body, "ssh_invalid_user_attempts_total", 1, map[string]string{
			"user": "hacker", "remote_ip": "10.0.0.99",
		})
	})

	t.Run("PreauthDisconnect", func(t *testing.T) {
		appendAuthLog(t, "Mar 27 12:03:00 server sshd[5003]: Disconnected from authenticating user root 10.0.0.1 port 22 [preauth]")

		body := scrapeMetricsRetry(t, func(b string) bool {
			_, found := findMetricValue(b, "ssh_preauth_disconnects_total", map[string]string{
				"user": "root", "remote_ip": "10.0.0.1",
			})
			return found
		}, 6)

		assertMetricValue(t, body, "ssh_preauth_disconnects_total", 1, map[string]string{
			"user": "root", "remote_ip": "10.0.0.1",
		})
	})

	t.Run("AuthFailurePAM", func(t *testing.T) {
		appendAuthLog(t, "Mar 27 12:04:00 server sshd[5010]: Failed keyboard-interactive/pam for pamuser from 10.0.0.50 port 22 ssh2")

		body := scrapeMetricsRetry(t, func(b string) bool {
			_, found := findMetricValue(b, "ssh_auth_failures_total", map[string]string{
				"user": "pamuser", "remote_ip": "10.0.0.50", "method": "keyboard-interactive/pam",
			})
			return found
		}, 6)

		assertMetricValue(t, body, "ssh_auth_failures_total", 1, map[string]string{
			"user": "pamuser", "remote_ip": "10.0.0.50", "method": "keyboard-interactive/pam",
		})
	})

	t.Run("AuthAttemptsBeforeSuccess", func(t *testing.T) {
		// Two failures then one success for the same sshd PID.
		appendAuthLog(t, "Mar 27 12:05:00 server sshd[6001]: Failed password for carol from 10.0.0.60 port 22 ssh2")
		appendAuthLog(t, "Mar 27 12:05:01 server sshd[6001]: Failed password for carol from 10.0.0.60 port 22 ssh2")
		appendAuthLog(t, "Mar 27 12:05:02 server sshd[6001]: Accepted password for carol from 10.0.0.60 port 22 ssh2")

		body := scrapeMetricsRetry(t, func(b string) bool {
			_, found := findMetricValue(b, "ssh_auth_attempts_before_success_count", map[string]string{
				"user": "carol",
			})
			return found
		}, 6)

		assertMetricValue(t, body, "ssh_auth_attempts_before_success_count", 1, map[string]string{
			"user": "carol",
		})
		assertMetricValue(t, body, "ssh_auth_attempts_before_success_sum", 2, map[string]string{
			"user": "carol",
		})
	})

	t.Run("LoginSetup_AcceptFirst", func(t *testing.T) {
		// Accept log line arrives first (sshd PID 7001).
		appendAuthLog(t, fmt.Sprintf("Mar 27 12:06:00 server sshd[7001]: Accepted publickey for dave from 10.0.0.70 port 22 ssh2"))

		// Wait for auth log ingestion.
		time.Sleep(500 * time.Millisecond)

		// Session appears in utmp with DIFFERENT PID (login shell PID).
		// Correlation uses {user, remoteIP}, not PID.
		writeUtmpRecords(t, []sessionSpec{
			{User: "dave", TTY: "pts/5", Host: "10.0.0.70", PID: 7099, TvSec: now + 2},
		})

		body := scrapeMetricsRetry(t, func(b string) bool {
			_, found := findMetricValue(b, "ssh_login_setup_seconds_count", map[string]string{
				"user": "dave",
			})
			return found
		}, 6)

		assertMetricGE(t, body, "ssh_login_setup_seconds_count", 1, map[string]string{
			"user": "dave",
		})
	})

	t.Run("LoginSetup_SessionFirst", func(t *testing.T) {
		// Session appears in utmp BEFORE accept log line.
		// First clear the previous dave session to avoid key collision.
		clearUtmp(t)
		triggerAndScrape(t)

		writeUtmpRecords(t, []sessionSpec{
			{User: "eve", TTY: "pts/6", Host: "10.0.0.80", PID: 8001, TvSec: now + 4},
		})

		// Scrape to trigger Collect() which parks the session in pendingSessions.
		triggerAndScrape(t)

		// Now the accept arrives with DIFFERENT sshd PID.
		// Correlation uses {user, remoteIP}, not PID.
		appendAuthLog(t, "Mar 27 12:07:00 server sshd[8099]: Accepted publickey for eve from 10.0.0.80 port 22 ssh2")

		// The Run() goroutine resolves the pending session.
		body := scrapeMetricsRetry(t, func(b string) bool {
			_, found := findMetricValue(b, "ssh_login_setup_seconds_count", map[string]string{
				"user": "eve",
			})
			return found
		}, 6)

		assertMetricGE(t, body, "ssh_login_setup_seconds_count", 1, map[string]string{
			"user": "eve",
		})
	})

	t.Run("ShortSession", func(t *testing.T) {
		// Clear previous state.
		clearUtmp(t)
		triggerAndScrape(t)

		// Write a session with a very recent timestamp.
		writeUtmpRecords(t, []sessionSpec{
			{User: "frank", TTY: "pts/7", Host: "10.0.0.90", PID: 9001, TvSec: int32(time.Now().Unix())},
		})

		// Scrape to register the session.
		triggerAndScrape(t)

		// End the session immediately (within 30s threshold).
		clearUtmp(t)

		body := triggerAndScrape(t)

		assertMetricGE(t, body, "ssh_short_sessions_total", 1, map[string]string{
			"user": "frank", "remote_ip": "10.0.0.90",
		})
	})
}
