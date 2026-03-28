//go:build e2e_rocky

package lima

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("ROCKY_LIMA_INSTANCE_PREFIX", "sshsess")
	t.Setenv("ROCKY_LIMA_KEEP_FAILED", "1")
	t.Setenv("ROCKY_LIMA_METRICS_PORT", "29842")
	t.Setenv("ROCKY_LIMA_SSH_PORT", "39222")

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv() error = %v", err)
	}

	if cfg.InstancePrefix != "sshsess" {
		t.Fatalf("InstancePrefix = %q, want %q", cfg.InstancePrefix, "sshsess")
	}
	if !cfg.KeepFailed {
		t.Fatal("KeepFailed = false, want true")
	}
	if cfg.MetricsPort != 29842 {
		t.Fatalf("MetricsPort = %d, want %d", cfg.MetricsPort, 29842)
	}
	if cfg.SSHPort != 39222 {
		t.Fatalf("SSHPort = %d, want %d", cfg.SSHPort, 39222)
	}
}

func TestRenderTemplate(t *testing.T) {
	cfg := config{
		InstancePrefix: "sshsess",
		MetricsPort:    29842,
		SSHPort:        39222,
	}

	rendered, err := renderTemplate(cfg, "sshsess-test", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey probe@test")
	if err != nil {
		t.Fatalf("renderTemplate() error = %v", err)
	}

	for _, needle := range []string{
		"template:rocky-9",
		"localPort: 39222",
		"guestPort: 9842",
		"hostPort: 29842",
		"authpriv.* /var/log/secure",
		"useradd -m probe",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey probe@test",
	} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("rendered template missing %q\n%s", needle, rendered)
		}
	}
}

func TestRockyLimaE2E_FailureArtifacts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Lima artifact test in short mode")
	}

	h, err := newHarness(t)
	if err != nil {
		t.Fatalf("newHarness() error = %v", err)
	}

	if err := h.Start(t); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	artifactDir := filepath.Join(t.TempDir(), "artifacts")
	if err := h.CollectArtifacts(artifactDir); err != nil {
		t.Fatalf("CollectArtifacts() error = %v", err)
	}

	for _, name := range []string{
		"secure.log",
		"journal-sshd.log",
		"who.log",
		"last-a.log",
		"utmp.hex",
		"exporter.log",
	} {
		path := filepath.Join(artifactDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("artifact %s missing: %v", name, err)
		}
	}
}

func TestRockyLimaE2E_PublicKeyLoginSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Lima e2e in short mode")
	}

	h, err := newHarness(t)
	if err != nil {
		t.Fatalf("newHarness() error = %v", err)
	}

	if err := h.Start(t); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	sessionDone, err := h.StartProbeSession(t)
	if err != nil {
		t.Fatalf("StartProbeSession() error = %v", err)
	}
	defer func() {
		if err := <-sessionDone; err != nil {
			t.Errorf("probe session error: %v", err)
		}
	}()

	if err := h.WaitForGuestAcceptance(t); err != nil {
		t.Fatalf("WaitForGuestAcceptance() error = %v", err)
	}

	if err := h.WaitForProbeSession(t); err != nil {
		t.Fatalf("WaitForProbeSession() error = %v", err)
	}

	metrics, err := h.WaitForMetrics(t, `ssh_auth_success_total{`, `ssh_login_setup_seconds_count{user="probe"}`)
	if err != nil {
		t.Fatalf("WaitForMetrics() error = %v", err)
	}
	if !strings.Contains(metrics, `method="publickey"`) || !strings.Contains(metrics, `user="probe"`) {
		t.Fatalf("probe publickey auth success not observed in metrics:\n%s", metrics)
	}
}
