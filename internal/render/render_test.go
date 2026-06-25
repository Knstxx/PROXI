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
	usersCSV := UsersCSV(state)
	if !strings.Contains(usersCSV, "vpn_admin,10001,ipsec-tproxy-vpn_admin") {
		t.Fatalf("users CSV must allocate per-user tproxy ports: %s", usersCSV)
	}
	firewall := FirewallScript(state)
	if !strings.Contains(firewall, `-j TPROXY --on-port "$TPROXY_PORT"`) {
		t.Fatalf("firewall TPROXY rule is missing: %s", firewall)
	}
	if !strings.Contains(firewall, `-m set --match-set "$PROXY_SET" dst -j TPROXY`) {
		t.Fatalf("selective firewall must proxy only kernel-set matches: %s", firewall)
	}
	if strings.Contains(firewall, `ipset flush "$PROXY_SET"`) || strings.Contains(firewall, `ipset flush "$DIRECT_SET"`) {
		t.Fatalf("firewall must not flush active ipsets referenced by live rules: %s", firewall)
	}
	if !strings.Contains(firewall, `ipset swap "$PROXY_SET_NEXT" "$PROXY_SET"`) || !strings.Contains(firewall, `ipset swap "$DIRECT_SET_NEXT" "$DIRECT_SET"`) {
		t.Fatalf("firewall must atomically swap prepared ipsets into live names: %s", firewall)
	}
	if !strings.Contains(firewall, `ipset restore -exist <"$proxy_restore"`) || !strings.Contains(firewall, `ipset restore -exist <"$direct_restore"`) {
		t.Fatalf("firewall must batch-load ipsets with ipset restore: %s", firewall)
	}
	if strings.Contains(firewall, `ipset add "$PROXY_SET_NEXT"`) || strings.Contains(firewall, `ipset add "$DIRECT_SET_NEXT"`) {
		t.Fatalf("firewall must not load large ipsets with one ipset add process per entry: %s", firewall)
	}
	if strings.Contains(firewall, `elif [[ "$MODE" == "selective" ]]; then
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -p udp --dport 53 -j RETURN
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -p tcp --dport 53 -j RETURN
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -m set --match-set "$DIRECT_SET" dst -j RETURN
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -p udp -j TPROXY`) {
		t.Fatalf("selective firewall must not proxy all UDP traffic: %s", firewall)
	}
	if !strings.Contains(firewall, `listen-address=$VPN_GATEWAY`) || !strings.Contains(firewall, `ipset=/whatismyipaddress.com/VPNPROXI_PROXY4`) {
		t.Fatalf("selective firewall must configure dnsmasq/ipset domain routing: %s", firewall)
	}
	if !strings.Contains(firewall, `awk -v set="$PROXY_SET"`) || strings.Contains(firewall, `done <"$GEODATA_DIR/ru-blocked-all.txt"`) {
		t.Fatalf("runet domain routing must be generated without a million-line bash loop: %s", firewall)
	}
	geodata := GeodataScript(state)
	if !strings.Contains(firewall, `ru-blocked-all.txt`) || !strings.Contains(geodata, `russia-blocked-geosite/release/ru-blocked-all.txt`) {
		t.Fatalf("runet blocked domains must feed dnsmasq/ipset routing")
	}
	if !strings.Contains(firewall, `ru-blocked-community.txt`) || !strings.Contains(geodata, `russia-blocked-geoip/release/text/ru-blocked-community.txt`) {
		t.Fatalf("runet community IP list must feed ipset routing")
	}
	if strings.Contains(geodata, `DOWNLOAD_XRAY_DAT="1"`) {
		t.Fatalf("selective mode must not require Xray .dat files for blocked-list routing: %s", geodata)
	}
	if !strings.Contains(geodata, `--connect-timeout 30`) || !strings.Contains(geodata, `--max-time 300`) || !strings.Contains(geodata, `--retry 3`) {
		t.Fatalf("geodata downloads must tolerate first-time large list refreshes: %s", geodata)
	}
	if !strings.Contains(geodata, `LIST_MAX_AGE_SECONDS=$((20 * 60 * 60))`) || !strings.Contains(geodata, `is_fresh "$SHARE_DIR/$name"`) {
		t.Fatalf("geodata downloads must skip fresh files during repeated apply: %s", geodata)
	}
	if !strings.Contains(firewall, `-d "$VPN_GATEWAY" -p udp --dport 53 -j ACCEPT`) {
		t.Fatalf("selective firewall must allow client DNS to the local resolver: %s", firewall)
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
	directSetAt := strings.LastIndex(updown, `--comment "vpnproxi user=$VPN_USER direct-set" -j RETURN`)
	proxySetAt := strings.Index(updown, `--comment "vpnproxi user=$VPN_USER xray-set-udp"`)
	if directSetAt < 0 || proxySetAt < 0 || directSetAt < proxySetAt {
		t.Fatalf("per-user direct-set RETURN must be inserted after proxy rules in script so iptables -I gives it higher priority: %s", updown)
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
		"updown.sh":   Updown(state),
		"firewall.sh": FirewallScript(state),
		"geodata.sh":  GeodataScript(state),
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
