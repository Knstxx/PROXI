package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnproxi/internal/core"
)

func TestCommandLine(t *testing.T) {
	t.Parallel()

	got := commandLine("systemctl", "restart", "xray")
	if got != "systemctl restart xray" {
		t.Fatalf("commandLine() = %q", got)
	}
}

func TestRunRequiredReturnsCommandFailure(t *testing.T) {
	t.Parallel()

	var res Result
	err := runRequired(&res, "sh", "-c", "echo fail >&2; exit 7")
	if err == nil {
		t.Fatal("runRequired() error = nil")
	}
	if !strings.Contains(err.Error(), "sh -c echo fail >&2; exit 7 failed: fail") {
		t.Fatalf("runRequired() error = %q", err)
	}
	if len(res.Commands) != 1 || res.Commands[0] != "sh -c echo fail >&2; exit 7" {
		t.Fatalf("runRequired() commands = %#v", res.Commands)
	}
}

func TestRunRequiredTimeoutStopsHungCommand(t *testing.T) {
	t.Parallel()

	var res Result
	err := runRequiredTimeout(&res, 10*time.Millisecond, "sh", "-c", "sleep 1")
	if err == nil {
		t.Fatal("runRequiredTimeout() error = nil")
	}
	if !strings.Contains(err.Error(), "timed out after") {
		t.Fatalf("runRequiredTimeout() error = %q", err)
	}
	if len(res.Commands) != 1 || res.Commands[0] != "sh -c sleep 1" {
		t.Fatalf("runRequiredTimeout() commands = %#v", res.Commands)
	}
}

func TestPrepareSwanctlCertificateSplitsBundle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	state := core.DefaultState()
	state.Server.CertFile = filepath.Join(dir, "vpnproxi-full.crt")
	state.Server.CAFile = filepath.Join(dir, "x509ca", "vpnproxi-ca.crt")
	bundle := strings.Join([]string{
		"-----BEGIN CERTIFICATE-----\nVEVTVC1MRUFG\n-----END CERTIFICATE-----\n",
		"-----BEGIN CERTIFICATE-----\nVEVTVC1JTlQ=\n-----END CERTIFICATE-----\n",
	}, "")
	if err := os.WriteFile(state.Server.CertFile, []byte(bundle), 0o644); err != nil {
		t.Fatal(err)
	}

	next, changed, err := prepareSwanctlCertificate(state)
	if err != nil {
		t.Fatal(err)
	}
	if next.Server.CertFile != filepath.Join(dir, "vpnproxi-leaf.crt") {
		t.Fatalf("CertFile = %q", next.Server.CertFile)
	}
	if len(changed) != 2 {
		t.Fatalf("changed files = %#v", changed)
	}
	if _, err := os.Stat(filepath.Join(dir, "vpnproxi-leaf.crt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x509ca", "vpnproxi-intermediate-1.crt")); err != nil {
		t.Fatal(err)
	}
}
