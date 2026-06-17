package render

import (
	"encoding/json"
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
		t.Fatalf("firewall must transparently capture UDP traffic as well: %s", firewall)
	}
	if !strings.Contains(firewall, `net.core.rmem_max=16777216`) || !strings.Contains(firewall, `net.ipv4.tcp_mtu_probing=1`) {
		t.Fatalf("firewall sysctl tuning for UDP buffers and MTU probing is missing: %s", firewall)
	}
	if !strings.Contains(firewall, `-j TCPMSS --clamp-mss-to-pmtu`) {
		t.Fatalf("firewall MSS clamping for VPN traffic is missing: %s", firewall)
	}
	updown := Updown(state)
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
	if !strings.Contains(enabled, "unique = replace") {
		t.Fatalf("swanctl config must replace stale mobile sessions: %s", enabled)
	}
}
