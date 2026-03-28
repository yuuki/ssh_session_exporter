//go:build e2e_rocky

package lima

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"
)

const (
	defaultInstancePrefix = "sshsess-rocky"
	defaultMetricsPort    = 39842
	defaultSSHPort        = 39222
	exporterPort          = 9842
)

//go:embed rocky-9.yaml.tmpl
var rocky9Template string

type config struct {
	InstancePrefix string
	KeepFailed     bool
	MetricsPort    int
	SSHPort        int
}

type harness struct {
	cfg             config
	instanceName    string
	workDir         string
	templatePath    string
	sshConfigFile   string
	probePrivateKey string
	probePublicKey  string
	repoRoot        string
	metricsURL      string
	cleanupOnce     sync.Once
}

type instanceInfo struct {
	Arch          string `json:"arch"`
	SSHConfigFile string `json:"sshConfigFile"`
}

type templateData struct {
	SSHPort            int
	MetricsPort        int
	ProbeAuthorizedKey string
}

func loadConfigFromEnv() (config, error) {
	cfg := config{
		InstancePrefix: getenvDefault("ROCKY_LIMA_INSTANCE_PREFIX", defaultInstancePrefix),
		KeepFailed:     parseBoolEnv(os.Getenv("ROCKY_LIMA_KEEP_FAILED")),
		MetricsPort:    defaultMetricsPort,
		SSHPort:        defaultSSHPort,
	}

	var err error
	if cfg.MetricsPort, err = getenvInt("ROCKY_LIMA_METRICS_PORT", cfg.MetricsPort); err != nil {
		return config{}, fmt.Errorf("parse ROCKY_LIMA_METRICS_PORT: %w", err)
	}
	if cfg.SSHPort, err = getenvInt("ROCKY_LIMA_SSH_PORT", cfg.SSHPort); err != nil {
		return config{}, fmt.Errorf("parse ROCKY_LIMA_SSH_PORT: %w", err)
	}

	return cfg, nil
}

func newHarness(t *testing.T) (*harness, error) {
	t.Helper()

	if !supportsHostOS(runtimeGOOS()) {
		t.Skip("Rocky Lima e2e requires a Linux or macOS host with limactl")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl is not installed")
	}

	cfg, err := loadConfigFromEnv()
	if err != nil {
		return nil, err
	}
	if err := ensurePortAvailable(cfg.MetricsPort); err != nil {
		return nil, fmt.Errorf("metrics port %d unavailable: %w", cfg.MetricsPort, err)
	}
	if err := ensurePortAvailable(cfg.SSHPort); err != nil {
		return nil, fmt.Errorf("ssh port %d unavailable: %w", cfg.SSHPort, err)
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		return nil, err
	}

	workDir := t.TempDir()
	instanceName := fmt.Sprintf("%s-%d", cfg.InstancePrefix, time.Now().UnixNano())
	privateKey := filepath.Join(workDir, "probe_key")
	publicKey := privateKey + ".pub"
	if err := generateProbeKeyPair(privateKey); err != nil {
		return nil, err
	}

	pub, err := os.ReadFile(publicKey)
	if err != nil {
		return nil, fmt.Errorf("read probe public key: %w", err)
	}

	rendered, err := renderTemplate(cfg, instanceName, strings.TrimSpace(string(pub)))
	if err != nil {
		return nil, err
	}

	templatePath := filepath.Join(workDir, "rocky-9.yaml")
	if err := os.WriteFile(templatePath, []byte(rendered), 0o644); err != nil {
		return nil, fmt.Errorf("write template: %w", err)
	}

	h := &harness{
		cfg:             cfg,
		instanceName:    instanceName,
		workDir:         workDir,
		templatePath:    templatePath,
		probePrivateKey: privateKey,
		probePublicKey:  publicKey,
		repoRoot:        repoRoot,
		metricsURL:      fmt.Sprintf("http://127.0.0.1:%d/metrics", cfg.MetricsPort),
	}

	t.Cleanup(func() {
		if t.Failed() {
			_ = h.CollectArtifacts(h.defaultArtifactDir())
		}
		h.Close()
	})

	return h, nil
}

func supportsHostOS(goos string) bool {
	return goos == "darwin" || goos == "linux"
}

var runtimeGOOS = func() string {
	return runtime.GOOS
}

func renderTemplate(cfg config, instanceName string, probeAuthorizedKey string) (string, error) {
	tpl, err := template.New("rocky").Parse(rocky9Template)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	data := templateData{
		SSHPort:            cfg.SSHPort,
		MetricsPort:        cfg.MetricsPort,
		ProbeAuthorizedKey: probeAuthorizedKey,
	}
	if err := tpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template for %s: %w", instanceName, err)
	}
	return buf.String(), nil
}

func (h *harness) Start(t *testing.T, exporterArgs ...string) error {
	t.Helper()

	if err := h.run("limactl", "create", "-y", "--name", h.instanceName, "--mount-none", h.templatePath); err != nil {
		return fmt.Errorf("limactl create: %w", err)
	}
	if err := h.run("limactl", "start", "-y", "--timeout", "10m", h.instanceName); err != nil {
		return fmt.Errorf("limactl start: %w", err)
	}

	info, err := h.instanceInfo()
	if err != nil {
		return err
	}
	h.sshConfigFile = info.SSHConfigFile
	if err := h.waitForGuestShell(2 * time.Minute); err != nil {
		return err
	}

	binaryPath := filepath.Join(h.workDir, "ssh_session_exporter")
	if err := buildExporterBinary(h.repoRoot, binaryPath, info.Arch); err != nil {
		return err
	}

	if err := h.run("limactl", "copy", "--backend=scp", binaryPath, h.instanceName+":/tmp/ssh_session_exporter"); err != nil {
		return fmt.Errorf("limactl copy exporter: %w", err)
	}
	if _, err := h.guestRootOutput("install -m 0755 /tmp/ssh_session_exporter /usr/local/bin/ssh_session_exporter"); err != nil {
		return fmt.Errorf("install exporter: %w", err)
	}
	if _, err := h.guestRootOutput("pkill -x ssh_session_exporter || true"); err != nil {
		return fmt.Errorf("stop previous exporter: %w", err)
	}
	exporterCmd := []string{
		"nohup",
		"/usr/local/bin/ssh_session_exporter",
		"--web.listen-address=:" + strconv.Itoa(exporterPort),
		"--auth-log.path=/var/log/secure",
	}
	exporterCmd = append(exporterCmd, exporterArgs...)
	exporterCmd = append(exporterCmd, ">/tmp/ssh_session_exporter.log", "2>&1", "<", "/dev/null", "&")
	if _, err := h.guestRootOutput(strings.Join(exporterCmd, " ")); err != nil {
		return fmt.Errorf("start exporter: %w", err)
	}
	if err := h.waitForHTTPReady(2 * time.Minute); err != nil {
		return err
	}

	return nil
}

func (h *harness) StartInteractiveProbeSession(t *testing.T) (<-chan error, error) {
	t.Helper()

	if h.sshConfigFile == "" {
		return nil, errors.New("ssh config file is empty")
	}

	cmd := exec.Command(
		"ssh",
		"-F", h.sshConfigFile,
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ControlPersist=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile="+filepath.Join(h.workDir, "known_hosts"),
		"-o", "User=probe",
		"-i", h.probePrivateKey,
		"-tt",
		h.sshAlias(),
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create probe ssh stdin pipe: %w", err)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start interactive probe ssh session: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		defer stdin.Close()
		_, _ = io.WriteString(stdin, "printf '__probe_ready__\\n'\n")
		_, _ = io.WriteString(stdin, "sleep 15\n")
		_, _ = io.WriteString(stdin, "exit\n")
	}()
	go func() {
		err := cmd.Wait()
		if err != nil {
			done <- fmt.Errorf("interactive probe ssh session failed: %w\n%s", err, out.String())
			return
		}
		done <- nil
	}()

	return done, nil
}

func (h *harness) StartProbeSession(t *testing.T) (<-chan error, error) {
	t.Helper()

	if h.sshConfigFile == "" {
		return nil, errors.New("ssh config file is empty")
	}

	cmd := exec.Command(
		"ssh",
		"-F", h.sshConfigFile,
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ControlPersist=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile="+filepath.Join(h.workDir, "known_hosts"),
		"-o", "User=probe",
		"-i", h.probePrivateKey,
		"-tt",
		h.sshAlias(),
		"sleep 15",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start probe ssh session: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		if err != nil {
			done <- fmt.Errorf("probe ssh session failed: %w\n%s", err, out.String())
			return
		}
		done <- nil
	}()

	return done, nil
}

func (h *harness) WaitForGuestAcceptance(t *testing.T) error {
	t.Helper()
	return waitFor(30*time.Second, 1*time.Second, func() error {
		out, err := h.guestRootOutput("grep -E 'Accepted publickey for probe from ' /var/log/secure")
		if err != nil {
			return err
		}
		if !strings.Contains(out, "Accepted publickey for probe") {
			return errors.New("Accepted line not present yet")
		}
		return nil
	})
}

func (h *harness) WaitForProbeSession(t *testing.T) error {
	t.Helper()
	return waitFor(30*time.Second, 1*time.Second, func() error {
		out, err := h.guestOutput("who")
		if err != nil {
			return err
		}
		if !strings.Contains(out, "probe") {
			return errors.New("probe session not in utmp yet")
		}
		return nil
	})
}

func (h *harness) WaitForMetrics(t *testing.T, needles ...string) (string, error) {
	t.Helper()
	var body string
	err := waitFor(45*time.Second, 1500*time.Millisecond, func() error {
		var err error
		body, err = h.doubleScrape()
		if err != nil {
			return err
		}
		for _, needle := range needles {
			if !strings.Contains(body, needle) {
				return fmt.Errorf("metric %q not observed yet", needle)
			}
		}
		return nil
	})
	return body, err
}

func (h *harness) CollectArtifacts(artifactDir string) error {
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return fmt.Errorf("create artifact dir: %w", err)
	}

	type artifact struct {
		name string
		cmd  string
		root bool
	}

	artifacts := []artifact{
		{name: "secure.log", cmd: "cat /var/log/secure", root: true},
		{name: "journal-sshd.log", cmd: "journalctl -u sshd --no-pager", root: true},
		{name: "who.log", cmd: "who"},
		{name: "last-a.log", cmd: "last -a"},
		{name: "utmp.hex", cmd: "sh -lc 'od -An -tx1 -N 512 /run/utmp 2>/dev/null || od -An -tx1 -N 512 /var/run/utmp 2>/dev/null'", root: true},
		{name: "exporter.log", cmd: "cat /tmp/ssh_session_exporter.log", root: true},
	}

	for _, artifact := range artifacts {
		var (
			out string
			err error
		)
		if artifact.root {
			out, err = h.guestRootOutput(artifact.cmd)
		} else {
			out, err = h.guestOutput(artifact.cmd)
		}
		if err != nil {
			out = err.Error() + "\n" + out
		}
		if writeErr := os.WriteFile(filepath.Join(artifactDir, artifact.name), []byte(out), 0o644); writeErr != nil {
			return fmt.Errorf("write artifact %s: %w", artifact.name, writeErr)
		}
	}

	return nil
}

func (h *harness) Close() {
	h.cleanupOnce.Do(func() {
		if h.cfg.KeepFailed {
			return
		}
		_ = h.run("limactl", "delete", "-f", h.instanceName)
	})
}

func (h *harness) defaultArtifactDir() string {
	return filepath.Join(h.repoRoot, ".e2e-artifacts", "rocky-lima", h.instanceName)
}

func (h *harness) instanceInfo() (instanceInfo, error) {
	out, err := exec.Command("limactl", "list", "--json", h.instanceName).CombinedOutput()
	if err != nil {
		return instanceInfo{}, fmt.Errorf("limactl list --json %s: %w\n%s", h.instanceName, err, string(out))
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var info instanceInfo
		if err := json.Unmarshal([]byte(line), &info); err != nil {
			return instanceInfo{}, fmt.Errorf("decode instance info: %w", err)
		}
		if info.SSHConfigFile != "" {
			return info, nil
		}
	}
	return instanceInfo{}, errors.New("instance info not found")
}

func (h *harness) waitForHTTPReady(timeout time.Duration) error {
	return waitFor(timeout, 1500*time.Millisecond, func() error {
		resp, err := http.Get(h.metricsURL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("metrics endpoint status = %d", resp.StatusCode)
		}
		return nil
	})
}

func (h *harness) waitForGuestShell(timeout time.Duration) error {
	return waitFor(timeout, 1500*time.Millisecond, func() error {
		if _, err := h.guestOutput("true"); err != nil {
			return err
		}
		if _, err := h.guestRootOutput("true"); err != nil {
			return err
		}
		return nil
	})
}

// doubleScrape scrapes twice because the first Collect() detects new/ended
// sessions via utmp diff, updating counters and histograms as a side-effect.
// The second scrape returns a response that includes both current gauge state
// and the just-updated counter/histogram values.
func (h *harness) doubleScrape() (string, error) {
	if _, err := h.scrapeMetrics(); err != nil {
		return "", err
	}
	return h.scrapeMetrics()
}

func (h *harness) scrapeMetrics() (string, error) {
	resp, err := http.Get(h.metricsURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (h *harness) guestOutput(command string) (string, error) {
	return h.runOutput("limactl", "shell", h.instanceName, "bash", "-lc", command)
}

func (h *harness) guestRootOutput(command string) (string, error) {
	return h.runOutput("limactl", "shell", h.instanceName, "sudo", "-n", "bash", "-lc", command)
}

func (h *harness) sshAlias() string {
	return "lima-" + h.instanceName
}

func (h *harness) run(cmd string, args ...string) error {
	_, err := h.runOutput(cmd, args...)
	return err
}

func (h *harness) runOutput(cmd string, args ...string) (string, error) {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w\n%s", cmd, strings.Join(args, " "), err, string(out))
	}
	return string(out), nil
}

func buildExporterBinary(repoRoot, outputPath, limaArch string) error {
	goarch, err := mapLimaArch(limaArch)
	if err != nil {
		return err
	}

	cmd := exec.Command("go", "build", "-o", outputPath, ".")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build GOARCH=%s: %w\n%s", goarch, err, string(out))
	}
	return nil
}

func mapLimaArch(limaArch string) (string, error) {
	switch limaArch {
	case "x86_64":
		return "amd64", nil
	case "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported Lima arch %q", limaArch)
	}
}

func findRepoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("failed to resolve current file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..")), nil
}

func generateProbeKeyPair(privateKeyPath string) error {
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", privateKeyPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh-keygen: %w\n%s", err, string(out))
	}
	return nil
}

func waitFor(timeout, interval time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(interval)
	}
	if lastErr == nil {
		lastErr = errors.New("timed out")
	}
	return lastErr
}

func ensurePortAvailable(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	return ln.Close()
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func parseBoolEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
