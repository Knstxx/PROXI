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
	} {
		if !strings.Contains(firewall, want) {
			t.Fatalf("selective firewall is missing %q: %s", want, firewall)
		}
	}
	if strings.Contains(firewall, `--match-set "$PROXY_SET" dst -j TPROXY`) || strings.Contains(firewall, `conf-file=/usr/local/etc/vpnproxi/dnsmasq-routes.conf`) {
		t.Fatalf("selective routing must no longer depend on dnsmasq/ipset classification: %s", firewall)
	}
	if !strings.Contains(firewall, `dns-forward-max=150`) || !strings.Contains(firewall, `max-tcp-connections=20`) {
		t.Fatalf("dnsmasq must bound whole-network DNS bursts: %s", firewall)
	}
	if !strings.Contains(firewall, `use-stale-cache=86400`) {
		t.Fatalf("dnsmasq must serve recently expired cache entries during brief upstream failures: %s", firewall)
	}
	if !strings.Contains(firewall, `server=127.0.0.1#5353`) {
		t.Fatalf("dnsmasq must use Xray's local encrypted DNS upstream: %s", firewall)
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
		`XRAY_RESTART_COOLDOWN=300`,
		`vpnproxi-health-${RANDOM}-$(date +%s).example.com`,
		`status: (NOERROR|NXDOMAIN)`,
		`systemctl restart vpnproxi-dnsmasq.service`,
		`systemctl restart xray.service`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("DNS health script is missing %q: %s", want, script)
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
