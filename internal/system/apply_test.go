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

func TestPrepareSwanctlCertificateStagesExternalBundleAndKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourceDir := filepath.Join(dir, "external")
	swanctlDir := filepath.Join(dir, "swanctl")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	state := core.DefaultState()
	state.Server.CertFile = filepath.Join(sourceDir, "vpnproxi-full.crt")
	state.Server.KeyFile = filepath.Join(sourceDir, "vpnproxi.key")
	state.Server.SwanctlPath = filepath.Join(swanctlDir, "swanctl.conf")
	bundle := strings.Join([]string{
		"-----BEGIN CERTIFICATE-----\nVEVTVC1MRUFG\n-----END CERTIFICATE-----\n",
		"-----BEGIN CERTIFICATE-----\nVEVTVC1JTlQ=\n-----END CERTIFICATE-----\n",
	}, "")
	if err := os.WriteFile(state.Server.CertFile, []byte(bundle), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state.Server.KeyFile, []byte("test-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	next, changed, err := prepareSwanctlCertificate(state)
	if err != nil {
		t.Fatal(err)
	}
	leafPath := filepath.Join(swanctlDir, "x509", "vpnproxi-leaf.crt")
	keyPath := filepath.Join(swanctlDir, "private", "vpnproxi.key")
	if next.Server.CertFile != leafPath {
		t.Fatalf("CertFile = %q", next.Server.CertFile)
	}
	if next.Server.KeyFile != keyPath {
		t.Fatalf("KeyFile = %q", next.Server.KeyFile)
	}
	if len(changed) != 3 {
		t.Fatalf("changed files = %#v", changed)
	}
	if _, err := os.Stat(leafPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(swanctlDir, "x509ca", "vpnproxi-intermediate-1.crt")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", info.Mode().Perm())
	}
}

func TestPrepareSwanctlCertificateKeepsStandardSingleCertificate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	swanctlDir := filepath.Join(dir, "swanctl")
	state := core.DefaultState()
	state.Server.CertFile = filepath.Join(swanctlDir, "x509", "vpnproxi-leaf.crt")
	state.Server.KeyFile = filepath.Join(swanctlDir, "private", "vpnproxi.key")
	state.Server.SwanctlPath = filepath.Join(swanctlDir, "swanctl.conf")
	if err := os.MkdirAll(filepath.Dir(state.Server.CertFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(state.Server.KeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state.Server.CertFile, []byte("single-certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state.Server.KeyFile, []byte("private-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	next, changed, err := prepareSwanctlCertificate(state)
	if err != nil {
		t.Fatal(err)
	}
	if next.Server.CertFile != state.Server.CertFile || next.Server.KeyFile != state.Server.KeyFile {
		t.Fatalf("paths changed: cert=%q key=%q", next.Server.CertFile, next.Server.KeyFile)
	}
	if len(changed) != 0 {
		t.Fatalf("changed files = %#v", changed)
	}
}

func TestCertificateRefreshUnitsUseDedicatedCommand(t *testing.T) {
	t.Parallel()

	service := certificateRefreshServiceUnit()
	if !strings.Contains(service, "ExecStart=/usr/local/bin/vpnproxi --refresh-certificate") {
		t.Fatalf("certificate refresh service = %q", service)
	}
	timer := certificateRefreshTimerUnit()
	if !strings.Contains(timer, "Persistent=true") || !strings.Contains(timer, "RandomizedDelaySec=30m") {
		t.Fatalf("certificate refresh timer = %q", timer)
	}
}

func TestRoutingServiceFollowsNetworkRestarts(t *testing.T) {
	t.Parallel()

	unit := routingServiceUnit()
	if !strings.Contains(unit, "PartOf=systemd-networkd.service NetworkManager.service") {
		t.Fatalf("routing service must restart with the network manager: %q", unit)
	}
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/vpnproxi-routing.sh") || !strings.Contains(unit, "RemainAfterExit=yes") {
		t.Fatalf("routing service must restore the policy route and remain active: %q", unit)
	}
}

func TestGeodataStatusPathsUseDatFilesForSelectiveMode(t *testing.T) {
	t.Parallel()

	state := core.DefaultState()
	state.Routes.Mode = "selective"
	state.Routes.UseRunetGeodata = true

	got := geodataStatusPaths(state)
	if len(got) != 2 || filepath.Base(got[0]) != "geoip.dat" || filepath.Base(got[1]) != "geosite.dat" {
		t.Fatalf("geodataStatusPaths() = %#v", got)
	}

	state.Routes.Mode = "direct"
	if got := geodataStatusPaths(state); len(got) != 0 {
		t.Fatalf("direct geodataStatusPaths() = %#v", got)
	}
}
