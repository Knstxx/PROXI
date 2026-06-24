package system

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"vpnproxi/internal/core"
	"vpnproxi/internal/render"
)

type Result struct {
	ChangedFiles []string `json:"changedFiles"`
	Commands     []string `json:"commands"`
	Warnings     []string `json:"warnings"`
}

func Apply(state core.State) (Result, error) {
	var res Result
	normalizedState, certFiles, err := prepareSwanctlCertificate(state)
	if err != nil {
		return res, err
	}
	state = normalizedState
	bundle, err := render.Build(state)
	if err != nil {
		return Result{}, err
	}
	res.ChangedFiles = append(res.ChangedFiles, certFiles...)
	writes := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{state.Server.XrayConfigPath, bundle.XrayConfig, 0o644},
		{state.Server.SwanctlPath, bundle.SwanctlConf, 0o644},
		{state.Server.UpdownPath, bundle.UpdownScript, 0o755},
		{state.Server.UsersCSVPath, bundle.UsersCSV, 0o600},
		{"/usr/local/bin/vpnproxi-geodata-update.sh", bundle.GeodataScript, 0o755},
		{"/usr/local/bin/vpnproxi-firewall.sh", bundle.FirewallScript, 0o755},
		{"/etc/systemd/system/vpnproxi-apply.service", []byte(applyServiceUnit()), 0o644},
		{"/etc/systemd/system/vpnproxi-geodata.service", []byte(geodataServiceUnit()), 0o644},
		{"/etc/systemd/system/vpnproxi-geodata.timer", []byte(geodataTimerUnit()), 0o644},
	}
	for _, w := range writes {
		if err := atomicWrite(w.path, w.data, w.mode); err != nil {
			return res, err
		}
		res.ChangedFiles = append(res.ChangedFiles, w.path)
	}
	if err := runRequired(&res, "/usr/local/bin/vpnproxi-firewall.sh"); err != nil {
		return res, err
	}
	if err := runRequired(&res, "systemctl", "daemon-reload"); err != nil {
		return res, err
	}
	if err := runRequired(&res, "systemctl", "enable", "vpnproxi-apply.service"); err != nil {
		return res, err
	}
	if err := runRequired(&res, "systemctl", "enable", "--now", "vpnproxi-geodata.timer"); err != nil {
		return res, err
	}
	if err := validateXrayConfig(&res, state.Server.XrayConfigPath); err != nil {
		return res, err
	}
	if err := runRequired(&res, "systemctl", "restart", "xray"); err != nil {
		return res, err
	}
	if err := runRequired(&res, "swanctl", "--load-conns"); err != nil {
		return res, err
	}
	if err := runRequired(&res, "swanctl", "--load-creds"); err != nil {
		return res, err
	}
	if err := runRequired(&res, "systemctl", "restart", "strongswan"); err != nil {
		return res, err
	}
	return res, nil
}

func Status() map[string]any {
	if runtime.GOOS != "linux" {
		return map[string]any{
			"platform": runtime.GOOS,
			"mode":     "local-only",
			"message":  "Host apply/status is Linux-only. UI, parsing and generated files work locally.",
		}
	}
	return map[string]any{
		"platform":       runtime.GOOS,
		"xray":           commandText("systemctl", "is-active", "xray"),
		"strongswan":     commandText("systemctl", "is-active", "strongswan"),
		"swanSAs":        commandText("swanctl", "--list-sas"),
		"tproxyRules":    commandText("iptables", "-t", "mangle", "-S", "PREROUTING"),
		"tproxyChain":    commandText("iptables", "-t", "mangle", "-S", "VPNPROXI_TPROXY"),
		"tproxyCounters": commandText("iptables", "-t", "mangle", "-L", "VPNPROXI_TPROXY", "-v", "-n", "-x", "--line-numbers"),
		"xrayStats":      commandText("xray", "api", "statsquery", "--server=127.0.0.1:10085", "-pattern", ""),
		"redirectRules":  commandText("iptables", "-t", "nat", "-S", "VPNPROXI_REDIRECT"),
		"natRules":       commandText("iptables", "-t", "nat", "-S", "POSTROUTING"),
		"netDev":         commandText("cat", "/proc/net/dev"),
	}
}

func ResetTraffic() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("traffic reset is Linux-only")
	}
	var res Result
	return runRequired(&res, "xray", "api", "statsquery", "--server=127.0.0.1:10085", "-pattern", "", "-reset")
}

func GeodataStatus(geodataDir string) map[string]any {
	meta := map[string]any{
		"geodataUpdatedAt": "",
		"geodataStatus":    "missing",
	}
	geoipPath := filepath.Join(geodataDir, "geoip.dat")
	geositePath := filepath.Join(geodataDir, "geosite.dat")
	latest := time.Time{}
	found := false
	for _, path := range []string{geoipPath, geositePath} {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		found = true
		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	if found {
		meta["geodataStatus"] = "ready"
		meta["geodataUpdatedAt"] = latest.UTC().Format(time.RFC3339)
	}
	return meta
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func prepareSwanctlCertificate(state core.State) (core.State, []string, error) {
	if state.Server.CertFile == "" {
		return state, nil, nil
	}
	data, err := os.ReadFile(state.Server.CertFile)
	if err != nil {
		return state, nil, err
	}
	certs := splitPEMCertificates(data)
	if len(certs) <= 1 {
		return state, nil, nil
	}

	certDir := filepath.Dir(state.Server.CertFile)
	caDir := filepath.Dir(state.Server.CAFile)
	if caDir == "." || caDir == string(filepath.Separator) || caDir == "" {
		caDir = "/etc/swanctl/x509ca"
	}
	leafPath := filepath.Join(certDir, certificateStem(state.Server.CertFile)+"-leaf.crt")
	if err := atomicWrite(leafPath, certs[0], 0o644); err != nil {
		return state, nil, err
	}
	changed := []string{leafPath}
	for i, cert := range certs[1:] {
		path := filepath.Join(caDir, fmt.Sprintf("%s-intermediate-%d.crt", certificateStem(state.Server.CertFile), i+1))
		if err := atomicWrite(path, cert, 0o644); err != nil {
			return state, changed, err
		}
		changed = append(changed, path)
	}
	state.Server.CertFile = leafPath
	return state, changed, nil
}

func splitPEMCertificates(data []byte) [][]byte {
	var certs [][]byte
	rest := data
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			return certs
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, pem.EncodeToMemory(block))
		}
		rest = next
	}
}

func certificateStem(path string) string {
	base := filepath.Base(path)
	for _, suffix := range []string{"-fullchain.pem", "-fullchain.crt", "-full.crt", ".pem", ".crt"} {
		if strings.HasSuffix(base, suffix) {
			return strings.TrimSuffix(base, suffix)
		}
	}
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func mustRun(name string, args ...string) []string {
	cmd := exec.Command(name, args...)
	_ = cmd.Run()
	return []string{commandLine(name, args...)}
}

func resetIPRule(mark string, table int) []string {
	tableText := strconv.Itoa(table)
	for {
		cmd := exec.Command("ip", "rule", "delete", "fwmark", mark, "table", tableText)
		if err := cmd.Run(); err != nil {
			break
		}
	}
	return mustRun("ip", "rule", "add", "fwmark", mark, "table", tableText)
}

func maybeRun(res *Result, name string, args ...string) []string {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s failed: %s", commandLine(name, args...), string(bytes.TrimSpace(out))))
	}
	return []string{commandLine(name, args...)}
}

func runRequired(res *Result, name string, args ...string) error {
	res.Commands = append(res.Commands, commandLine(name, args...))
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(out))
	if message == "" {
		message = err.Error()
	}
	return fmt.Errorf("%s failed: %s", commandLine(name, args...), message)
}

func runRequiredTimeout(res *Result, timeout time.Duration, name string, args ...string) error {
	res.Commands = append(res.Commands, commandLine(name, args...))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s timed out after %s", commandLine(name, args...), timeout)
	}
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(out))
	if message == "" {
		message = err.Error()
	}
	return fmt.Errorf("%s failed: %s", commandLine(name, args...), message)
}

func validateXrayConfig(res *Result, configPath string) error {
	const validateTimeout = 15 * time.Second

	help, err := exec.Command("xray", "help", "run").CombinedOutput()
	res.Commands = append(res.Commands, "xray help run")
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("xray help run failed: %s", strings.TrimSpace(string(help))))
		return nil
	}
	if !strings.Contains(string(help), "-test") {
		res.Warnings = append(res.Warnings, "installed Xray does not support run -test; skipping pre-restart validation")
		return nil
	}
	if err := runRequiredTimeout(res, validateTimeout, "xray", "run", "-test", "-config", configPath); err != nil {
		if strings.Contains(err.Error(), "timed out after") {
			res.Warnings = append(res.Warnings, err.Error())
			return nil
		}
		return err
	}
	return nil
}

func commandText(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return err.Error()
	}
	return string(bytes.TrimSpace(out))
}

func commandLine(name string, args ...string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}

func geodataServiceUnit() string {
	return `[Unit]
Description=VPNproxi geodata update

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpnproxi-geodata-update.sh
`
}

func applyServiceUnit() string {
	return `[Unit]
Description=VPNproxi host apply
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/vpnproxi/vpnproxi.env
ExecStart=/usr/local/bin/vpnproxi --apply-once

[Install]
WantedBy=multi-user.target
`
}

func geodataTimerUnit() string {
	return `[Unit]
Description=Run VPNproxi geodata update daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
`
}
