//go:build e2e

package e2e

import (
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

func writeUtmpRecords(t *testing.T, records []sessionSpec) {
	t.Helper()
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal records: %v", err)
	}

	fullArgs := []string{
		"compose", "-f", composeDir + "/docker-compose.e2e.yml",
		"exec", "-T", "exporter",
		"utmpwriter", "--path=/data/utmp", "--action=write",
	}
	cmd := exec.Command("docker", fullArgs...)
	cmd.Stdin = strings.NewReader(string(data))
	out, err := cmd.CombinedOutput()
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

// findMetricExists checks if any metric line with the given name (and optional labels) exists.
func findMetricExists(body, name string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !strings.HasPrefix(line, name) {
			continue
		}
		rest := line[len(name):]
		if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '{') {
			return true
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
}
