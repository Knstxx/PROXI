package render

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"vpnproxi/internal/core"
	"vpnproxi/internal/link"
)

func TestXrayConfigContainsTransparentInboundAndOutboundMark(t *testing.T) {
	state := core.DefaultState()
	state.Server.Users = []core.VPNUser{{Login: "vpn_admin", Password: "change-me-now"}}
	state.Routes.Mode = "selective"
	state.Routes.DirectDomains = []string{"domain:youtube.com"}
	out, err := link.Parse("vless://11111111-2222-4333-8444-555555555555@example.com:443?type=tcp&security=none#node")
	if err != nil {
		t.Fatal(err)
	}
	state.Outbound = out
	raw, err := XrayConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds := cfg["inbounds"].([]any)
	first := inbounds[0].(map[string]any)
	if first["tag"] != "ipsec-tproxy" {
		t.Fatalf("tag=%v", first["tag"])
	}
	settings := first["settings"].(map[string]any)
	if settings["network"] != "tcp,udp" || settings["followRedirect"] != true {
		t.Fatalf("unexpected transparent inbound settings: %#v", settings)
	}
	streamSettings := first["streamSettings"].(map[string]any)
	inboundSockopt := streamSettings["sockopt"].(map[string]any)
	if inboundSockopt["tproxy"] != "tproxy" {
		t.Fatalf("transparent inbound must use TPROXY sockopt: %#v", inboundSockopt)
	}
	outbounds := cfg["outbounds"].([]any)
	proxy := outbounds[1].(map[string]any)
	stream := proxy["streamSettings"].(map[string]any)
	sockopt := stream["sockopt"].(map[string]any)
	if sockopt["mark"].(float64) != 2 {
		t.Fatalf("missing outbound mark: %#v", sockopt)
	}
	if _, ok := cfg["stats"].(map[string]any); !ok {
		t.Fatalf("xray stats must be enabled: %#v", cfg)
	}
	if _, ok := cfg["burstObservatory"]; ok {
		t.Fatalf("single-outbound configs must not run xray burst observatory probes: %#v", cfg["burstObservatory"])
	}
	routing := cfg["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	firstRule := rules[0].(map[string]any)
	if firstRule["outboundTag"] != "api" {
		t.Fatalf("first routing rule must expose xray API, got %#v", firstRule)
	}
	lastRule := rules[len(rules)-1].(map[string]any)
	if lastRule["ruleTag"] != "selective-direct-default-vpn_admin" || lastRule["outboundTag"] != "direct-vpn_admin" {
		t.Fatalf("selective mode must default each client to direct after proxy matches, got %#v", lastRule)
	}
	if !strings.Contains(string(raw), `"geosite:ru-blocked-all"`) || !strings.Contains(string(raw), `"geoip:ru-blocked-community"`) {
		t.Fatalf("selective mode must evaluate the maintained blocked categories inside Xray: %s", raw)
	}
	usersCSV := UsersCSV(state)
	if !strings.Contains(usersCSV, "vpn_admin,10001,ipsec-tproxy-vpn_admin") {
		t.Fatalf("users CSV must allocate per-user tproxy ports: %s", usersCSV)
	}
	firewall := FirewallScript(state)
	for _, want := range []string{
		`-p udp -j TPROXY --on-port "$TPROXY_PORT"`,
		`-p tcp -j TPROXY --on-port "$TPROXY_PORT"`,
		`-m addrtype --dst-type LOCAL -j RETURN`,
		`-d 10.0.0.0/8 -j RETURN`,
		`-d 192.168.0.0/16 -j RETURN`,
		`listen-address=$VPN_GATEWAY`,
		`ExecStartPre=/bin/sh -c 'until /usr/sbin/ip -4 -o addr show dev lo | /usr/bin/grep -q " 10.10.10.1/32 "; do /usr/bin/sleep 1; done'`,
		`test -s /run/vpnproxi/dns-upstreams.conf || install -m 0644 /usr/local/etc/vpnproxi/dns-upstreams-primary.conf /run/vpnproxi/dns-upstreams.conf`,
		`TimeoutStartSec=75`,
		`exec 8>/run/vpnproxi/dns-health.lock`,
		`initial_upstream_mode=primary`,
		`initial_upstream_mode=fallback`,
		`for initial_query_type in A TXT; do`,
		`probe_initial_resolver 127.0.0.1 5353 primary`,
		`initial_all_unavailable=1`,
		`: >/run/vpnproxi/dns-fallback-unavailable`,
	} {
		if !strings.Contains(firewall, want) {
			t.Fatalf("selective firewall is missing %q: %s", want, firewall)
		}
	}
	if strings.Contains(firewall, `--match-set "$PROXY_SET" dst -j TPROXY`) || strings.Contains(firewall, `conf-file=/usr/local/etc/vpnproxi/dnsmasq-routes.conf`) {
		t.Fatalf("selective routing must no longer depend on dnsmasq/ipset classification: %s", firewall)
	}
	if !strings.Contains(firewall, `dns-forward-max=512`) || !strings.Contains(firewall, `max-tcp-connections=64`) {
		t.Fatalf("dnsmasq must bound whole-network DNS bursts: %s", firewall)
	}
	if !strings.Contains(firewall, `use-stale-cache=86400`) {
		t.Fatalf("dnsmasq must serve recently expired cache entries during brief upstream failures: %s", firewall)
	}
	if !strings.Contains(firewall, `bogus-priv`) || !strings.Contains(firewall, `local=/local/`) {
		t.Fatalf("dnsmasq must terminate private reverse and .local lookups locally: %s", firewall)
	}
	if !strings.Contains(firewall, `server=127.0.0.1#5353`) || !strings.Contains(firewall, `servers-file=/run/vpnproxi/dns-upstreams.conf`) {
		t.Fatalf("dnsmasq must use Xray's local encrypted DNS upstream: %s", firewall)
	}
	for _, want := range []string{
		`dns-upstreams-fallback-cloudflare.conf`,
		`dns-upstreams-fallback-google.conf`,
		`server=1.1.1.1#53`,
		`server=8.8.8.8#53`,
	} {
		if !strings.Contains(firewall, want) {
			t.Fatalf("dnsmasq must install a deterministic direct fallback when the encrypted upstream stalls; missing %q: %s", want, firewall)
		}
	}
	if strings.Contains(firewall, `strict-order`) || strings.Contains(firewall, `all-servers`) || strings.Contains(firewall, `fast-dns-retry`) {
		t.Fatalf("dnsmasq must switch its servers-file explicitly instead of racing or waiting indefinitely on upstreams: %s", firewall)
	}
	primaryAt := strings.Index(firewall, `server=127.0.0.1#5353`)
	cloudflareFallbackAt := strings.Index(firewall, `server=1.1.1.1#53`)
	googleFallbackAt := strings.Index(firewall, `server=8.8.8.8#53`)
	if primaryAt < 0 || cloudflareFallbackAt < primaryAt || googleFallbackAt < cloudflareFallbackAt {
		t.Fatalf("encrypted DNS must remain first, followed by direct fallbacks: %s", firewall)
	}
	if !strings.Contains(firewall, `address=/eokai.com/#`) {
		t.Fatalf("dnsmasq must answer the known broken delegation locally: %s", firewall)
	}
	if !strings.Contains(firewall, `rm -f /usr/local/etc/vpnproxi/dnsmasq-routes.conf`) {
		t.Fatalf("firewall must remove obsolete large DNS routing artifacts: %s", firewall)
	}
	geodata := GeodataScript(state)
	if !strings.Contains(geodata, `DOWNLOAD_XRAY_DAT="1"`) || !strings.Contains(geodata, `russia-v2ray-rules-dat/release/geoip.dat`) || !strings.Contains(geodata, `russia-v2ray-rules-dat/release/geosite.dat`) {
		t.Fatalf("selective mode must refresh Xray geodata files: %s", geodata)
	}
	if strings.Contains(geodata, `fetch_text_list`) || strings.Contains(geodata, `russia-blocked-geosite/release/ru-blocked-all.txt`) {
		t.Fatalf("geodata refresh must not retain obsolete text-list routing: %s", geodata)
	}
	if !strings.Contains(geodata, `--connect-timeout 30`) || !strings.Contains(geodata, `--max-time 300`) || !strings.Contains(geodata, `--retry 3`) {
		t.Fatalf("geodata downloads must tolerate transient network failures: %s", geodata)
	}
	if !strings.Contains(geodata, `LIST_MAX_AGE_SECONDS=$((20 * 60 * 60))`) || !strings.Contains(geodata, `is_fresh "$SHARE_DIR/geoip.dat"`) {
		t.Fatalf("geodata downloads must skip fresh files during repeated apply: %s", geodata)
	}
	if !strings.Contains(firewall, `-d "$VPN_GATEWAY" -p udp --dport 53 -j ACCEPT`) {
		t.Fatalf("selective firewall must allow client DNS to the local resolver: %s", firewall)
	}
	if !strings.Contains(string(raw), `"https://1.1.1.1/dns-query"`) || !strings.Contains(string(raw), `"enableParallelQuery": true`) {
		t.Fatalf("xray must resolve client A/AAAA queries over parallel DoH: %s", raw)
	}
	if !strings.Contains(string(raw), `"tag": "dns-cache"`) || !strings.Contains(string(raw), `"tag": "dns-cache-out"`) {
		t.Fatalf("xray must expose the local DNS bridge used by dnsmasq: %s", raw)
	}
	if !strings.Contains(firewall, `ip rule add fwmark "$TPROXY_MARK" table "$TPROXY_TABLE"`) {
		t.Fatalf("firewall policy route rule is missing: %s", firewall)
	}
	if !strings.Contains(firewall, `-m mark --mark ${TPROXY_MARK}/0xffffffff -j ACCEPT`) {
		t.Fatalf("firewall INPUT allow for marked transparent traffic is missing: %s", firewall)
	}
	if strings.Contains(firewall, `iptables -I INPUT 1 -s "$VPN_SUBNET" -j ACCEPT`) {
		t.Fatalf("firewall must not allow all VPN client traffic into local INPUT: %s", firewall)
	}
	if !strings.Contains(firewall, `-p udp -j TPROXY --on-port "$TPROXY_PORT"`) {
		t.Fatalf("firewall force mode branch must transparently capture UDP traffic: %s", firewall)
	}
	if !strings.Contains(firewall, `net.core.rmem_max=16777216`) || !strings.Contains(firewall, `net.ipv4.tcp_mtu_probing=1`) {
		t.Fatalf("firewall sysctl tuning for UDP buffers and MTU probing is missing: %s", firewall)
	}
	if !strings.Contains(firewall, `-j TCPMSS --clamp-mss-to-pmtu`) {
		t.Fatalf("firewall MSS clamping for VPN traffic is missing: %s", firewall)
	}
	updown := Updown(state)
	if !strings.Contains(firewall, `FWD_CHAIN="VPNPROXI_FORWARD"`) || !strings.Contains(updown, `FWD_CHAIN="VPNPROXI_FORWARD"`) {
		t.Fatalf("client traffic accounting must use a project-owned forward chain")
	}
	catchAllAt := strings.LastIndex(updown, `--comment "vpnproxi user=$VPN_USER xray-udp"`)
	localAt := strings.LastIndex(updown, `--comment "vpnproxi user=$VPN_USER direct-local"`)
	dnsAt := strings.LastIndex(updown, `--comment "vpnproxi user=$VPN_USER direct-dns"`)
	if catchAllAt < 0 || localAt < catchAllAt || dnsAt < localAt {
		t.Fatalf("per-user local and DNS bypasses must be inserted after catch-all rules so -I gives them priority: %s", updown)
	}
	if strings.Contains(updown, `| grep -- "-s ${PLUTO_PEER_SOURCEIP}/32"`) {
		t.Fatalf("updown cleanup must remove per-user rules explicitly instead of parsing iptables output: %s", updown)
	}
	if !strings.Contains(updown, `while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -p udp -m comment --comment "vpnproxi user=$VPN_USER xray-udp"`) {
		t.Fatalf("updown cleanup must delete per-user UDP TPROXY rules: %s", updown)
	}
}

func TestDirectModeDoesNotRequireOutbound(t *testing.T) {
	state := core.DefaultState()
	state.Outbound = nil
	raw, err := XrayConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	outbounds := cfg["outbounds"].([]any)
	if len(outbounds) != 2 {
		t.Fatalf("direct mode should only render direct and block outbounds, got %d", len(outbounds))
	}
	firewall := FirewallScript(state)
	if !strings.Contains(firewall, `MODE="direct"`) {
		t.Fatalf("firewall script does not include direct mode: %s", firewall)
	}
	if !strings.Contains(firewall, `-s "$VPN_SUBNET" -j RETURN`) {
		t.Fatalf("direct firewall bypass is missing: %s", firewall)
	}
	if !strings.Contains(firewall, `ipset destroy "$PROXY_SET"`) || !strings.Contains(firewall, `ipset destroy "$DIRECT_SET"`) {
		t.Fatalf("direct mode must clear stale selective ipsets: %s", firewall)
	}
}

func TestForceModeKeepsXrayDatForRunetRules(t *testing.T) {
	state := core.DefaultState()
	state.Routes.Mode = "force_proxy"
	state.Routes.UseRunetGeodata = true
	out, err := link.Parse("vless://11111111-2222-4333-8444-555555555555@example.com:443?type=tcp&security=none#node")
	if err != nil {
		t.Fatal(err)
	}
	state.Outbound = out

	geodata := GeodataScript(state)
	if !strings.Contains(geodata, `DOWNLOAD_XRAY_DAT="1"`) {
		t.Fatalf("force mode must keep Xray .dat downloads for geosite/geoip routing: %s", geodata)
	}
	xray, err := XrayConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(xray), `geoip:ru-blocked-community`) || !strings.Contains(string(xray), `geosite:ru-blocked-all`) {
		t.Fatalf("force mode must render Xray runet categories: %s", xray)
	}
	if !strings.Contains(string(xray), `"ruleTag": "force-proxy-default"`) {
		t.Fatalf("force mode must keep its final external-outbound rule: %s", xray)
	}
	updown := Updown(state)
	if !strings.Contains(updown, `--comment "vpnproxi user=$VPN_USER xray-udp"`) || !strings.Contains(updown, `--comment "vpnproxi user=$VPN_USER direct-local"`) {
		t.Fatalf("force mode must use the common Xray datapath with local-network bypasses: %s", updown)
	}
}

func TestSelectiveCustomGeodataRulesDownloadDatFiles(t *testing.T) {
	state := core.DefaultState()
	state.Routes.Mode = "selective"
	state.Routes.UseRunetGeodata = false
	state.Routes.ProxyDomains = []string{"geosite:youtube"}
	state.Routes.ProxyIPs = []string{"geoip:google"}

	if got := GeodataScript(state); !strings.Contains(got, `DOWNLOAD_XRAY_DAT="1"`) {
		t.Fatalf("custom Xray categories must enable .dat downloads: %s", got)
	}

	state.Routes.Mode = "direct"
	if got := GeodataScript(state); !strings.Contains(got, `DOWNLOAD_XRAY_DAT="0"`) {
		t.Fatalf("direct mode must not download unused Xray geodata: %s", got)
	}
}

func TestGeneratedShellScriptsHaveValidSyntax(t *testing.T) {
	state := core.DefaultState()
	state.Routes.Mode = "selective"
	state.Server.Users = []core.VPNUser{{Login: "vpn_admin", Password: "change-me-now"}}
	out, err := link.Parse("vless://11111111-2222-4333-8444-555555555555@example.com:443?type=tcp&security=none#node")
	if err != nil {
		t.Fatal(err)
	}
	state.Outbound = out

	for name, script := range map[string]string{
		"updown.sh":     Updown(state),
		"firewall.sh":   FirewallScript(state),
		"geodata.sh":    GeodataScript(state),
		"routing.sh":    RoutingScript(state),
		"dns-health.sh": DNSHealthScript(state),
	} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("%s has invalid bash syntax: %v\n%s", name, err, out)
		}
	}
}

func TestDNSHealthScriptUsesConsecutiveFailuresAndRecoveryCooldown(t *testing.T) {
	state := core.DefaultState()
	state.Routes.Mode = "selective"
	script := DNSHealthScript(state)
	for _, want := range []string{
		`FAILURE_THRESHOLD=2`,
		`DNSMASQ_RESTART_COOLDOWN=120`,
		`DNS_SERVER="${VPNPROXI_DNS_HEALTH_SERVER:-10.10.10.1}"`,
		`DNS_PORT="${VPNPROXI_DNS_HEALTH_PORT:-53}"`,
		`PRIMARY_DNS_SERVER="${VPNPROXI_DNS_PRIMARY_SERVER:-127.0.0.1}"`,
		`PRIMARY_DNS_PORT="${VPNPROXI_DNS_PRIMARY_PORT:-5353}"`,
		`probe_name="vpnproxi-${label}-${query_type}-${RANDOM}-$(date +%s).example.com"`,
		`PRIMARY_FAIL_THRESHOLD="${VPNPROXI_DNS_PRIMARY_FAIL_THRESHOLD:-2}"`,
		`RECOVERY_SUCCESS_THRESHOLD="${VPNPROXI_DNS_RECOVERY_SUCCESS_THRESHOLD:-6}"`,
		`MIN_FALLBACK_DWELL="${VPNPROXI_DNS_MIN_FALLBACK_DWELL:-120}"`,
		`status: (NOERROR|NXDOMAIN)`,
		`if (( probe_ok == 1 )); then`,
		`UPSTREAM_FILE="$STATE_DIR/dns-upstreams.conf"`,
		`UPSTREAM_APPLIED_FILE="$STATE_DIR/dns-upstream-applied"`,
		`activate_upstreams "$selected_fallback_file" fallback`,
		`recovery_successes >= RECOVERY_SUCCESS_THRESHOLD`,
		`systemctl kill --kill-who=main --signal=HUP vpnproxi-dnsmasq.service`,
		`encrypted DNS primary degraded; activated $selected_fallback_name DNS fallback`,
		`DNS failover thresholds and dwell must be greater than zero`,
		`repair_upstream_templates`,
		`repaired DNS upstream template`,
		`resolver recovery cooling down; no restart`,
		`Maximum number of concurrent DNS queries reached`,
		`queue_saturated`,
		`systemctl restart vpnproxi-dnsmasq.service`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("DNS health script is missing %q: %s", want, script)
		}
	}
	if strings.Contains(script, `systemctl restart xray.service`) {
		t.Fatalf("DNS recovery must not restart the shared Xray datapath: %s", script)
	}
}

func TestDNSHealthScriptFailoverStateMachine(t *testing.T) {
	state := core.DefaultState()
	state.Routes.Mode = "selective"

	root := t.TempDir()
	stateDir := filepath.Join(root, "run")
	etcDir := filepath.Join(root, "etc")
	binDir := filepath.Join(root, "bin")
	for _, dir := range []string{stateDir, etcDir, binDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(raw))
	}

	primary := filepath.Join(etcDir, "dns-upstreams-primary.conf")
	cloudflare := filepath.Join(etcDir, "dns-upstreams-fallback-cloudflare.conf")
	google := filepath.Join(etcDir, "dns-upstreams-fallback-google.conf")
	active := filepath.Join(stateDir, "dns-upstreams.conf")
	modeFile := filepath.Join(stateDir, "dns-upstream-mode")
	appliedFile := filepath.Join(stateDir, "dns-upstream-applied")
	upstreamState := filepath.Join(stateDir, "dns-upstream.state")
	write(primary, "server=127.0.0.1#5353\n", 0o644)
	write(cloudflare, "server=1.1.1.1#53\n", 0o644)
	write(google, "server=8.8.8.8#53\n", 0o644)
	write(active, read(primary)+"\n", 0o644)
	write(modeFile, "primary\n", 0o644)
	write(appliedFile, "primary\n", 0o644)
	write(upstreamState, "primary 0 0 0\n", 0o644)

	systemctlLog := filepath.Join(root, "systemctl.log")
	digLog := filepath.Join(root, "dig.log")
	hupFailFile := filepath.Join(root, "fail-hup")
	write(filepath.Join(binDir, "systemctl"), `#!/bin/bash
set -euo pipefail
case "${1:-}" in
  is-active) exit 0 ;;
  kill)
    if [[ -e "$FAKE_HUP_FAIL_FILE" ]]; then
      echo HUP_FAIL >> "$FAKE_SYSTEMCTL_LOG"
      exit 1
    fi
    echo HUP >> "$FAKE_SYSTEMCTL_LOG"
    exit 0
    ;;
  restart)
    echo "RESTART ${*:2}" >> "$FAKE_SYSTEMCTL_LOG"
    exit 0
    ;;
  *) exit 0 ;;
esac
`, 0o755)
	write(filepath.Join(binDir, "dig"), `#!/bin/bash
set -euo pipefail
server=""
for arg in "$@"; do
  [[ "$arg" == @* ]] && server="${arg#@}"
done
case "$server" in
  127.0.0.1) status="${FAKE_PRIMARY:-up}" ;;
  1.1.1.1) status="${FAKE_CLOUDFLARE:-up}" ;;
  8.8.8.8) status="${FAKE_GOOGLE:-up}" ;;
  10.10.10.1) status="${FAKE_CLIENT:-up}" ;;
  *) status=down ;;
esac
echo "$server $status" >> "$FAKE_DIG_LOG"
[[ "$status" == up ]] || exit 9
echo ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1'
`, 0o755)
	write(filepath.Join(binDir, "logger"), "#!/bin/bash\nexit 0\n", 0o755)
	write(filepath.Join(binDir, "journalctl"), "#!/bin/bash\nexit 0\n", 0o755)
	write(filepath.Join(binDir, "flock"), "#!/bin/bash\nexit 0\n", 0o755)
	write(filepath.Join(binDir, "timeout"), "#!/bin/bash\nshift\nexec \"$@\"\n", 0o755)

	script := DNSHealthScript(state)
	script = strings.ReplaceAll(script, "/run/vpnproxi", stateDir)
	script = strings.ReplaceAll(script, "/usr/local/etc/vpnproxi", etcDir)
	scriptPath := filepath.Join(root, "dns-health.sh")
	write(scriptPath, script, 0o755)

	run := func(expectSuccess bool, overrides ...string) string {
		t.Helper()
		cmd := exec.Command("bash", scriptPath)
		values := map[string]string{
			"PATH":                     binDir + ":" + os.Getenv("PATH"),
			"FAKE_SYSTEMCTL_LOG":       systemctlLog,
			"FAKE_HUP_FAIL_FILE":       hupFailFile,
			"FAKE_DIG_LOG":             digLog,
			"FAKE_PRIMARY":             "up",
			"FAKE_CLOUDFLARE":          "up",
			"FAKE_GOOGLE":              "up",
			"FAKE_CLIENT":              "up",
			"VPNPROXI_DNS_HEALTH_PORT": "53",
		}
		for _, override := range overrides {
			parts := strings.SplitN(override, "=", 2)
			values[parts[0]] = parts[1]
		}
		cmd.Env = nil
		for _, item := range os.Environ() {
			parts := strings.SplitN(item, "=", 2)
			if _, overridden := values[parts[0]]; !overridden {
				cmd.Env = append(cmd.Env, item)
			}
		}
		for key, value := range values {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
		out, err := cmd.CombinedOutput()
		if expectSuccess && err != nil {
			t.Fatalf("health script failed: %v\n%s", err, out)
		}
		if !expectSuccess && err == nil {
			t.Fatalf("health script unexpectedly succeeded:\n%s", out)
		}
		return string(out)
	}
	hupCount := func() int {
		raw, err := os.ReadFile(systemctlLog)
		if os.IsNotExist(err) {
			return 0
		}
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "HUP" {
				count++
			}
		}
		return count
	}

	// Two consecutive primary failures activate one verified fallback.
	run(true, "FAKE_PRIMARY=down")
	if got := read(upstreamState); !strings.HasPrefix(got, "primary 1 0 ") {
		t.Fatalf("first failure state = %q; dig log=%q", got, read(digLog))
	}
	if got := hupCount(); got != 0 {
		t.Fatalf("HUP count after one failure = %d", got)
	}
	run(true, "FAKE_PRIMARY=down")
	if got := read(active); got != read(cloudflare) || read(modeFile) != "fallback" || read(appliedFile) != "cloudflare" {
		t.Fatalf("fallback not applied: active=%q mode=%q applied=%q", got, read(modeFile), read(appliedFile))
	}
	if got := hupCount(); got != 1 {
		t.Fatalf("HUP count after failover = %d", got)
	}

	// Recovery uses consecutive successes and switches back only once.
	write(upstreamState, "fallback 0 0 0\n", 0o644)
	run(true, "VPNPROXI_DNS_RECOVERY_SUCCESS_THRESHOLD=2", "VPNPROXI_DNS_MIN_FALLBACK_DWELL=1")
	if read(modeFile) != "fallback" {
		t.Fatalf("recovered before success threshold")
	}
	run(true, "VPNPROXI_DNS_RECOVERY_SUCCESS_THRESHOLD=2", "VPNPROXI_DNS_MIN_FALLBACK_DWELL=1")
	if got := read(active); got != read(primary) || read(modeFile) != "primary" || read(appliedFile) != "primary" {
		t.Fatalf("primary not restored: active=%q mode=%q applied=%q", got, read(modeFile), read(appliedFile))
	}

	// If rename succeeded but HUP failed, the marker mismatch forces a retry.
	write(active, read(cloudflare)+"\n", 0o644)
	write(modeFile, "fallback\n", 0o644)
	write(appliedFile, "primary\n", 0o644)
	write(upstreamState, "fallback 0 0 0\n", 0o644)
	write(hupFailFile, "fail\n", 0o600)
	run(false, "FAKE_PRIMARY=down")
	if read(appliedFile) != "primary" {
		t.Fatalf("failed HUP advanced applied marker")
	}
	if err := os.Remove(hupFailFile); err != nil {
		t.Fatal(err)
	}
	run(true, "FAKE_PRIMARY=down")
	if read(appliedFile) != "cloudflare" {
		t.Fatalf("HUP retry did not advance marker")
	}

	// A non-empty corrupt active file is repaired from a validated template.
	write(active, "not-a-dnsmasq-server\n", 0o644)
	write(appliedFile, "cloudflare\n", 0o644)
	run(true)
	if got := read(active); got != read(primary) || read(appliedFile) != "primary" {
		t.Fatalf("corrupt active file not repaired: active=%q applied=%q", got, read(appliedFile))
	}

	// Zero thresholds are rejected and no unverified fallback is activated.
	run(false, "VPNPROXI_DNS_PRIMARY_FAIL_THRESHOLD=0")
	write(active, read(primary)+"\n", 0o644)
	write(modeFile, "primary\n", 0o644)
	write(appliedFile, "primary\n", 0o644)
	write(upstreamState, "primary 0 0 0\n", 0o644)
	run(true,
		"FAKE_PRIMARY=down",
		"FAKE_CLOUDFLARE=down",
		"FAKE_GOOGLE=down",
		"VPNPROXI_DNS_PRIMARY_FAIL_THRESHOLD=1",
	)
	if read(modeFile) != "primary" {
		t.Fatalf("activated an unverified fallback")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "dns-fallback-unavailable")); err != nil {
		t.Fatalf("missing all-upstreams-down marker: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "dns-primary-degraded")); err != nil {
		t.Fatalf("missing primary-degraded marker: %v", err)
	}

	// A healthy primary clears stale incident markers without a service restart.
	run(true)
	for _, marker := range []string{"dns-primary-degraded", "dns-fallback-unavailable"} {
		if _, err := os.Stat(filepath.Join(stateDir, marker)); !os.IsNotExist(err) {
			t.Fatalf("stale marker %s was not cleared: %v", marker, err)
		}
	}
}

func TestRoutingScriptRestoresPolicyRouteAfterNetworkRestart(t *testing.T) {
	state := core.DefaultState()
	script := RoutingScript(state)
	for _, want := range []string{
		`flock -x 9`,
		`ip rule add priority "$TPROXY_PRIORITY" fwmark "$TPROXY_MARK" table "$TPROXY_TABLE"`,
		`ip route replace local 0.0.0.0/0 dev lo table "$TPROXY_TABLE"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("routing script is missing %q: %s", want, script)
		}
	}
}

func TestSwanctlMobikeFlagFollowsState(t *testing.T) {
	state := core.DefaultState()
	state.Server.MobikeEnabled = false
	disabled := Swanctl(state)
	if !strings.Contains(disabled, "mobike = no") {
		t.Fatalf("swanctl config must disable MOBIKE when the flag is off: %s", disabled)
	}

	state.Server.MobikeEnabled = true
	enabled := Swanctl(state)
	if !strings.Contains(enabled, "mobike = yes") {
		t.Fatalf("swanctl config must enable MOBIKE when the flag is on: %s", enabled)
	}
	if !strings.Contains(enabled, "dpd_delay = 0s") {
		t.Fatalf("swanctl config must not actively probe idle mobile clients: %s", enabled)
	}
	if !strings.Contains(enabled, "dpd_action = clear") {
		t.Fatalf("swanctl config must clear stale child SAs instead of trapping them: %s", enabled)
	}
	if !strings.Contains(enabled, "close_action = start") {
		t.Fatalf("swanctl config must restart a child SA closed by the peer: %s", enabled)
	}
	if !strings.Contains(enabled, "unique = replace") {
		t.Fatalf("swanctl config must replace stale mobile sessions: %s", enabled)
	}
}

func TestSwanctlPoolExcludesGatewayAddress(t *testing.T) {
	state := core.DefaultState()
	state.Server.VPNSubnet = "10.10.10.0/24"

	got := Swanctl(state)
	if !strings.Contains(got, "vpn-pool { addrs = 10.10.10.2-10.10.10.254") {
		t.Fatalf("swanctl pool must not lease the local gateway address: %s", got)
	}
	if strings.Contains(got, "vpn-pool { addrs = 10.10.10.0/24") {
		t.Fatalf("swanctl pool must not use the whole subnet as lease range: %s", got)
	}
}
