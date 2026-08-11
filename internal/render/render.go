package render

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"vpnproxi/internal/core"
)

const (
	tproxyInboundTag  = "ipsec-tproxy"
	proxyOutboundTag  = "proxy-primary"
	directOutboundTag = "direct"
	blockOutboundTag  = "block"
	dnsInboundTag     = "dns-cache"
	dnsOutboundTag    = "dns-cache-out"
	dnsInboundPort    = 5353
	proxySetName      = "VPNPROXI_PROXY4"
	directSetName     = "VPNPROXI_DIRECT4"
)

type Bundle struct {
	XrayConfig      []byte
	SwanctlConf     []byte
	UpdownScript    []byte
	UsersCSV        []byte
	GeodataScript   []byte
	DNSHealthScript []byte
	FirewallScript  []byte
	RoutingScript   []byte
}

func Build(state core.State) (Bundle, error) {
	xray, err := XrayConfig(state)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		XrayConfig:      xray,
		SwanctlConf:     []byte(Swanctl(state)),
		UpdownScript:    []byte(Updown(state)),
		UsersCSV:        []byte(UsersCSV(state)),
		GeodataScript:   []byte(GeodataScript(state)),
		DNSHealthScript: []byte(DNSHealthScript(state)),
		FirewallScript:  []byte(FirewallScript(state)),
		RoutingScript:   []byte(RoutingScript(state)),
	}, nil
}

func XrayConfig(state core.State) ([]byte, error) {
	if state.Routes.Mode != "direct" && state.Outbound == nil {
		return nil, fmt.Errorf("outbound is not configured")
	}
	rules := []map[string]any{
		{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
	}
	if state.Routes.Mode != "direct" {
		rules = append(rules,
			map[string]any{"type": "field", "inboundTag": []string{dnsInboundTag}, "outboundTag": dnsOutboundTag},
			map[string]any{"type": "field", "inboundTag": []string{"dns-upstream"}, "outboundTag": proxyOutboundTag},
		)
	}
	rules = append(rules, map[string]any{"type": "field", "network": "udp", "port": "53", "outboundTag": directOutboundTag})
	if state.Routes.BlockPrivateIPs {
		rules = append(rules, map[string]any{
			"ruleTag":     "block-private",
			"type":        "field",
			"ip":          []string{"geoip:private"},
			"outboundTag": blockOutboundTag,
		})
	}
	if len(state.Routes.DirectDomains) > 0 {
		rules = appendDirectRules(rules, state, "direct-domains", "domain", state.Routes.DirectDomains)
	}
	if len(state.Routes.DirectIPs) > 0 {
		rules = appendDirectRules(rules, state, "direct-ips", "ip", state.Routes.DirectIPs)
	}
	if state.Routes.Mode != "direct" && len(state.Routes.ProxyDomains) > 0 {
		rules = appendProxyRules(rules, state, "force-proxy-domains", "domain", state.Routes.ProxyDomains)
	}
	if state.Routes.Mode != "direct" && len(state.Routes.ProxyIPs) > 0 {
		rules = appendProxyRules(rules, state, "force-proxy-ips", "ip", state.Routes.ProxyIPs)
	}
	if state.Routes.Mode != "direct" && len(state.Routes.ProxyPorts) > 0 {
		rules = appendProxyRules(rules, state, "force-proxy-ports", "port", joinPorts(state.Routes.ProxyPorts))
	}
	if state.Routes.Mode != "direct" && state.Routes.UseRunetGeodata {
		rules = appendProxyRules(rules, state, "runetfreedom-geosite", "domain", []string{"geosite:ru-blocked-all"})
		rules = appendProxyRules(rules, state, "runetfreedom-geoip", "ip", []string{"geoip:ru-blocked", "geoip:ru-blocked-community", "geoip:telegram"})
	}
	if state.Routes.Mode == "force_proxy" {
		rules = appendProxyRules(rules, state, "force-proxy-default", "", nil)
	}
	if state.Routes.Mode == "selective" {
		rules = appendDirectRules(rules, state, "selective-direct-default", "", nil)
	}
	outbounds := []any{
		directOutbound(directOutboundTag),
	}
	if state.Outbound != nil {
		outbounds = append(outbounds, proxyOutbound(state, proxyOutboundTag))
		for _, user := range state.Server.Users {
			outbounds = append(outbounds, directOutbound(userDirectOutboundTag(user.Login)))
			outbounds = append(outbounds, proxyOutbound(state, userProxyOutboundTag(user.Login)))
		}
	}
	if state.Routes.Mode != "direct" {
		outbounds = append(outbounds, map[string]any{
			"tag":      dnsOutboundTag,
			"protocol": "dns",
			"settings": map[string]any{
				"rewriteAddress": "1.1.1.1",
				"rewritePort":    53,
				"rules": []any{
					map[string]any{"action": "hijack", "qType": "1,28"},
					map[string]any{"action": "direct"},
				},
			},
		})
	}
	outbounds = append(outbounds, map[string]any{"tag": blockOutboundTag, "protocol": "blackhole"})
	inbounds := []any{tproxyInbound(tproxyInboundTag, state.Server.TProxyPort)}
	for i, user := range state.Server.Users {
		inbounds = append(inbounds, tproxyInbound(userInboundTag(user.Login), userTProxyPort(state, i)))
	}
	if state.Routes.Mode != "direct" {
		inbounds = append(inbounds, map[string]any{
			"tag":      dnsInboundTag,
			"listen":   "127.0.0.1",
			"port":     dnsInboundPort,
			"protocol": "dokodemo-door",
			"settings": map[string]any{
				"address": "1.1.1.1",
				"port":    53,
				"network": "tcp,udp",
			},
		})
	}
	inbounds = append(inbounds, map[string]any{"tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}})
	config := map[string]any{
		"log":      map[string]any{"loglevel": "warning", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log"},
		"api":      map[string]any{"tag": "api", "services": []string{"HandlerService", "RoutingService", "StatsService"}},
		"policy":   map[string]any{"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true}},
		"stats":    map[string]any{},
		"routing":  map[string]any{"domainStrategy": "IPIfNonMatch", "rules": rules},
		"inbounds": inbounds, "outbounds": outbounds,
	}
	if state.Routes.Mode != "direct" {
		config["dns"] = map[string]any{
			"servers": []any{
				map[string]any{"address": "https://1.1.1.1/dns-query", "timeoutMs": 2500},
				map[string]any{"address": "https://8.8.8.8/dns-query", "timeoutMs": 2500},
			},
			"tag":                 "dns-upstream",
			"queryStrategy":       "UseIP",
			"enableParallelQuery": true,
			"serveStale":          true,
			"serveExpiredTTL":     86400,
		}
	}
	return json.MarshalIndent(config, "", "  ")
}

func tproxyInbound(tag string, port int) map[string]any {
	return map[string]any{
		"tag": tag, "listen": "0.0.0.0", "port": port, "protocol": "dokodemo-door",
		"settings":       map[string]any{"network": "tcp,udp", "followRedirect": true},
		"sniffing":       map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
		"streamSettings": map[string]any{"sockopt": map[string]any{"tproxy": "tproxy"}},
	}
}

func proxyOutbound(state core.State, tag string) map[string]any {
	proxy := map[string]any{
		"tag":      tag,
		"protocol": state.Outbound.Protocol,
		"settings": cloneMap(state.Outbound.Settings),
	}
	if len(state.Outbound.StreamSettings) > 0 {
		proxy["streamSettings"] = withOutboundMark(cloneMap(state.Outbound.StreamSettings))
	} else {
		proxy["streamSettings"] = map[string]any{"sockopt": map[string]any{"mark": 2}}
	}
	return proxy
}

func directOutbound(tag string) map[string]any {
	return map[string]any{"tag": tag, "protocol": "freedom", "streamSettings": map[string]any{"sockopt": map[string]any{"mark": 2}}}
}

func appendDirectRules(rules []map[string]any, state core.State, ruleTag, field string, value any) []map[string]any {
	rules = appendDirectRule(rules, ruleTag, field, value, []string{tproxyInboundTag}, directOutboundTag)
	for _, user := range state.Server.Users {
		rules = appendDirectRule(rules, ruleTag+"-"+safeTag(user.Login), field, value, []string{userInboundTag(user.Login)}, userDirectOutboundTag(user.Login))
	}
	return rules
}

func appendDirectRule(rules []map[string]any, ruleTag, field string, value any, inboundTags []string, outboundTag string) []map[string]any {
	rule := map[string]any{"ruleTag": ruleTag, "type": "field", "inboundTag": inboundTags, "outboundTag": outboundTag}
	if field != "" {
		rule[field] = value
	}
	return append(rules, rule)
}

func appendProxyRules(rules []map[string]any, state core.State, ruleTag, field string, value any) []map[string]any {
	rules = appendProxyRule(rules, ruleTag, field, value, tproxyInboundTag, proxyOutboundTag)
	for _, user := range state.Server.Users {
		rules = appendProxyRule(rules, ruleTag+"-"+safeTag(user.Login), field, value, userInboundTag(user.Login), userProxyOutboundTag(user.Login))
	}
	return rules
}

func appendProxyRule(rules []map[string]any, ruleTag, field string, value any, inboundTag, outboundTag string) []map[string]any {
	rule := map[string]any{"ruleTag": ruleTag, "type": "field", "inboundTag": []string{inboundTag}, "outboundTag": outboundTag}
	if field != "" {
		rule[field] = value
	}
	return append(rules, rule)
}

func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	raw, _ := json.Marshal(src)
	dst := map[string]any{}
	_ = json.Unmarshal(raw, &dst)
	return dst
}

func Swanctl(state core.State) string {
	var b strings.Builder
	domain := state.Server.VPNDomain
	if domain == "" {
		domain = "%any"
	}
	certFile := filepath.Base(state.Server.CertFile)
	if certFile == "." || certFile == string(filepath.Separator) {
		certFile = state.Server.CertFile
	}
	fmt.Fprintf(&b, "connections {\n")
	writeSwanctlConnection(&b, "ikev2-eap", domain, certFile, state.Server.UpdownPath, state.Server.MobikeEnabled)
	fmt.Fprintf(&b, "\n")
	writeSwanctlConnection(&b, "ikev2-eap-any", "%any", certFile, state.Server.UpdownPath, state.Server.MobikeEnabled)
	fmt.Fprintf(&b, "}\n\n")
	fmt.Fprintf(&b, "pools {\n  vpn-pool { addrs = %s\n    dns = %s\n  }\n}\n\n", vpnPoolAddrs(state.Server.VPNSubnet), strings.Join(vpnDNSServers(state), ", "))
	fmt.Fprintf(&b, "secrets {\n")
	for _, user := range state.Server.Users {
		fmt.Fprintf(&b, "  eap-%s {\n    id = %s\n    secret = %q\n  }\n", user.Login, user.Login, user.Password)
	}
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func writeSwanctlConnection(b *strings.Builder, name, localID, certFile, updownPath string, mobikeEnabled bool) {
	const ikeProposals = "aes256gcm16-prfsha384-ecp256,aes256-sha256-modp2048,aes256-sha384-ecp384,aes256-sha256-ecp256,aes128-sha256-modp2048,aes256-sha256-modp1024,aes128-sha256-modp1024"
	const espProposals = "aes256gcm16-ecp256,aes256gcm16,aes256-sha256-ecp256,aes256-sha256-modp2048,aes256-sha256-modp1024,aes128-sha256-modp1024,aes256-sha256-modpnone,aes128-sha256-modpnone,aes256-sha1-modpnone,aes128-sha1-modpnone,3des-sha1-modpnone"
	mobike := "no"
	if mobikeEnabled {
		mobike = "yes"
	}
	fmt.Fprintf(b, "  %s {\n", name)
	fmt.Fprintf(b, "    local_addrs = %%any\n    version = 2\n    fragmentation = yes\n    mobike = %s\n    dpd_delay = 0s\n    proposals = %s\n    send_cert = always\n    pools = vpn-pool\n    unique = replace\n", mobike, ikeProposals)
	fmt.Fprintf(b, "    local { auth = pubkey\n      certs = %s\n      id = %s\n    }\n", certFile, localID)
	fmt.Fprintf(b, "    remote { auth = eap-mschapv2\n      eap_id = %%any\n      id = %%any\n    }\n")
	fmt.Fprintf(b, "    children { net { local_ts = 0.0.0.0/0\n      esp_proposals = %s\n      updown = %s\n      rekey_time = 48h\n      close_action = start\n      dpd_action = clear\n    } }\n", espProposals, updownPath)
	fmt.Fprintf(b, "  }\n")
}

func Updown(state core.State) string {
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
MODE=%q
USERS_CSV=%q
CHAIN="VPNPROXI_TPROXY"
FWD_CHAIN="VPNPROXI_FORWARD"
PROXY_SET=%q
DIRECT_SET=%q
TPROXY_MARK=%q
VPN_USER="${PLUTO_XAUTH_ID:-$PLUTO_PEER_ID}"
logger -t vpnproxi-updown "$PLUTO_VERB user=$VPN_USER ip=$PLUTO_PEER_SOURCEIP"
TPROXY_PORT=$(grep -v '^#' "$USERS_CSV" | awk -F',' -v user="$VPN_USER" '$1 == user { print $2; exit }')
if [[ -z "${TPROXY_PORT:-}" ]]; then
  logger -t vpnproxi-updown "no route for user=$VPN_USER"
  exit 0
fi
modprobe xt_TPROXY 2>/dev/null || true
modprobe nf_tproxy_ipv4 2>/dev/null || true
iptables -t mangle -N "$CHAIN" 2>/dev/null || true
iptables -t mangle -C PREROUTING -j "$CHAIN" 2>/dev/null || iptables -t mangle -I PREROUTING 1 -j "$CHAIN"
iptables -t mangle -N "$FWD_CHAIN" 2>/dev/null || true
iptables -t mangle -C FORWARD -j "$FWD_CHAIN" 2>/dev/null || iptables -t mangle -I FORWARD 1 -j "$FWD_CHAIN"
flush_rules() {
  while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -p udp --dport 53 -m comment --comment "vpnproxi user=$VPN_USER direct-dns" -j RETURN 2>/dev/null; do :; done
  while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -p tcp --dport 53 -m comment --comment "vpnproxi user=$VPN_USER direct-dns" -j RETURN 2>/dev/null; do :; done
  while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -m addrtype --dst-type LOCAL -m comment --comment "vpnproxi user=$VPN_USER direct-local" -j RETURN 2>/dev/null; do :; done
  for subnet in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -d "$subnet" -m comment --comment "vpnproxi user=$VPN_USER direct-private" -j RETURN 2>/dev/null; do :; done
  done
  while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -m set --match-set "$DIRECT_SET" dst -m comment --comment "vpnproxi user=$VPN_USER direct-set" -j RETURN 2>/dev/null; do :; done
  while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -p udp -m set --match-set "$PROXY_SET" dst -m comment --comment "vpnproxi user=$VPN_USER xray-set-udp" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark ${TPROXY_MARK}/0xffffffff 2>/dev/null; do :; done
  while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -p tcp -m set --match-set "$PROXY_SET" dst -m comment --comment "vpnproxi user=$VPN_USER xray-set-tcp" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark ${TPROXY_MARK}/0xffffffff 2>/dev/null; do :; done
  while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -p udp -m comment --comment "vpnproxi user=$VPN_USER xray-udp" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark ${TPROXY_MARK}/0xffffffff 2>/dev/null; do :; done
  while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -p tcp -m comment --comment "vpnproxi user=$VPN_USER xray-tcp" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark ${TPROXY_MARK}/0xffffffff 2>/dev/null; do :; done
  while iptables -t mangle -D "$FWD_CHAIN" -s "$PLUTO_PEER_SOURCEIP" -m comment --comment "vpnproxi user=$VPN_USER direct-upload" -j RETURN 2>/dev/null; do :; done
  while iptables -t mangle -D "$FWD_CHAIN" -d "$PLUTO_PEER_SOURCEIP" -m comment --comment "vpnproxi user=$VPN_USER direct-download" -j RETURN 2>/dev/null; do :; done
  while iptables -t mangle -D "$CHAIN" -s "$PLUTO_PEER_SOURCEIP" -m comment --comment "vpnproxi user=$VPN_USER direct-all" -j RETURN 2>/dev/null; do :; done
}
case "$PLUTO_VERB" in
  up-client)
    flush_rules
    if [[ "$MODE" == "direct" ]]; then
      iptables -t mangle -I "$CHAIN" 1 -s "$PLUTO_PEER_SOURCEIP" -m comment --comment "vpnproxi user=$VPN_USER direct-all" -j RETURN
    else
      iptables -t mangle -I "$CHAIN" 1 -s "$PLUTO_PEER_SOURCEIP" -p tcp -m comment --comment "vpnproxi user=$VPN_USER xray-tcp" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark ${TPROXY_MARK}/0xffffffff
      iptables -t mangle -I "$CHAIN" 1 -s "$PLUTO_PEER_SOURCEIP" -p udp -m comment --comment "vpnproxi user=$VPN_USER xray-udp" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark ${TPROXY_MARK}/0xffffffff
      for subnet in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
        iptables -t mangle -I "$CHAIN" 1 -s "$PLUTO_PEER_SOURCEIP" -d "$subnet" -m comment --comment "vpnproxi user=$VPN_USER direct-private" -j RETURN
      done
      iptables -t mangle -I "$CHAIN" 1 -s "$PLUTO_PEER_SOURCEIP" -m addrtype --dst-type LOCAL -m comment --comment "vpnproxi user=$VPN_USER direct-local" -j RETURN
      iptables -t mangle -I "$CHAIN" 1 -s "$PLUTO_PEER_SOURCEIP" -p tcp --dport 53 -m comment --comment "vpnproxi user=$VPN_USER direct-dns" -j RETURN
      iptables -t mangle -I "$CHAIN" 1 -s "$PLUTO_PEER_SOURCEIP" -p udp --dport 53 -m comment --comment "vpnproxi user=$VPN_USER direct-dns" -j RETURN
    fi
    iptables -t mangle -I "$FWD_CHAIN" 1 -s "$PLUTO_PEER_SOURCEIP" -m comment --comment "vpnproxi user=$VPN_USER direct-upload" -j RETURN
    iptables -t mangle -I "$FWD_CHAIN" 2 -d "$PLUTO_PEER_SOURCEIP" -m comment --comment "vpnproxi user=$VPN_USER direct-download" -j RETURN
    logger -t vpnproxi-updown "routing mode=$MODE user=$VPN_USER ip=$PLUTO_PEER_SOURCEIP counters installed"
    ;;
  down-client)
    flush_rules
    ;;
esac
`, routeMode(state), state.Server.UsersCSVPath, proxySetName, directSetName, state.Server.TProxyMark)
}

func UsersCSV(state core.State) string {
	var b strings.Builder
	b.WriteString("# login,tproxy_port,tag\n")
	for i, user := range state.Server.Users {
		fmt.Fprintf(&b, "%s,%d,%s\n", user.Login, userTProxyPort(state, i), userInboundTag(user.Login))
	}
	return b.String()
}

func userTProxyPort(state core.State, index int) int {
	return state.Server.TProxyPort + index + 1
}

func userInboundTag(login string) string {
	return "ipsec-tproxy-" + safeTag(login)
}

func userProxyOutboundTag(login string) string {
	return "proxy-" + safeTag(login)
}

func userDirectOutboundTag(login string) string {
	return "direct-" + safeTag(login)
}

func safeTag(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	if b.Len() == 0 {
		return "user"
	}
	return b.String()
}

func FirewallScript(state core.State) string {
	gatewayIP := vpnGatewayIP(state.Server.VPNSubnet)
	if gatewayIP == "" {
		gatewayIP = "10.10.10.1"
	}
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
MODE=%q
VPN_SUBNET=%q
VPN_GATEWAY=%q
TPROXY_PORT=%q
TPROXY_MARK=%q
TPROXY_TABLE=%d
CHAIN="VPNPROXI_TPROXY"
FWD_CHAIN="VPNPROXI_FORWARD"
REDIRECT_CHAIN="VPNPROXI_REDIRECT"
PROXY_SET=%q
DIRECT_SET=%q
PROXY_SET_NEXT="${PROXY_SET}_NEXT"
DIRECT_SET_NEXT="${DIRECT_SET}_NEXT"
WAN_IFACE=$(ip route show default 0.0.0.0/0 | awk '{print $5; exit}')
if [[ -z "${WAN_IFACE:-}" ]]; then
  WAN_IFACE=$(ip route | awk '/default/ { print $5; exit }')
fi
if [[ -z "${WAN_IFACE:-}" ]]; then
  echo "cannot detect default interface" >&2
  exit 1
fi

modprobe xt_TPROXY 2>/dev/null || true
modprobe nf_tproxy_ipv4 2>/dev/null || true
cat >/etc/modules-load.d/vpnproxi-tproxy.conf <<'MODULES'
xt_TPROXY
nf_tproxy_ipv4
nf_tproxy_ipv6
MODULES

cat >/etc/sysctl.d/99-vpnproxi.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.default.route_localnet=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.netdev_max_backlog=8192
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
net.ipv4.tcp_mtu_probing=1
SYSCTL
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.all.route_localnet=1 net.ipv4.conf.default.route_localnet=1 >/dev/null
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 net.core.netdev_max_backlog=8192 >/dev/null
sysctl -w net.ipv4.udp_rmem_min=16384 net.ipv4.udp_wmem_min=16384 net.ipv4.tcp_mtu_probing=1 >/dev/null
sysctl -w "net.ipv4.conf.${WAN_IFACE}.rp_filter=0" "net.ipv4.conf.${WAN_IFACE}.route_localnet=1" >/dev/null 2>&1 || true

while ip rule delete fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" 2>/dev/null; do :; done
ip rule add fwmark "$TPROXY_MARK" table "$TPROXY_TABLE"
ip route replace local 0.0.0.0/0 dev lo table "$TPROXY_TABLE"
ip addr add "$VPN_GATEWAY/32" dev lo 2>/dev/null || true

if [[ "$MODE" != "direct" ]]; then
  command -v dnsmasq >/dev/null 2>&1 || { echo "dnsmasq is required for the VPN DNS cache" >&2; exit 1; }
  install -d -m 0755 /usr/local/etc/vpnproxi
  rm -f /usr/local/etc/vpnproxi/dnsmasq-routes.conf /usr/local/etc/vpnproxi/dnsmasq-direct-domains.txt
  cat >/usr/local/etc/vpnproxi/dnsmasq.conf <<DNSMASQ
listen-address=$VPN_GATEWAY
bind-interfaces
no-hosts
no-resolv
bogus-priv
local=/local/
cache-size=10000
dns-forward-max=512
max-tcp-connections=64
neg-ttl=60
use-stale-cache=86400
address=/eokai.com/#
server=127.0.0.1#%d
DNSMASQ
  cat >/etc/systemd/system/vpnproxi-dnsmasq.service <<'DNSMASQ_SERVICE'
[Unit]
Description=VPNproxi local DNS cache
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/usr/local/etc/vpnproxi/dnsmasq.conf --pid-file=/run/vpnproxi-dnsmasq.pid
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
DNSMASQ_SERVICE
  systemctl daemon-reload
  systemctl enable vpnproxi-dnsmasq >/dev/null 2>&1 || true
  systemctl restart vpnproxi-dnsmasq
else
  systemctl stop vpnproxi-dnsmasq 2>/dev/null || true
  rm -f /usr/local/etc/vpnproxi/dnsmasq-routes.conf /usr/local/etc/vpnproxi/dnsmasq-direct-domains.txt
fi

iptables -t mangle -N "$CHAIN" 2>/dev/null || true
iptables -t mangle -F "$CHAIN"
iptables -t mangle -C PREROUTING -j "$CHAIN" 2>/dev/null || iptables -t mangle -I PREROUTING 1 -j "$CHAIN"
iptables -t mangle -N "$FWD_CHAIN" 2>/dev/null || true
iptables -t mangle -F "$FWD_CHAIN"
iptables -t mangle -C FORWARD -j "$FWD_CHAIN" 2>/dev/null || iptables -t mangle -I FORWARD 1 -j "$FWD_CHAIN"
iptables -t nat -N "$REDIRECT_CHAIN" 2>/dev/null || true
iptables -t nat -F "$REDIRECT_CHAIN"
while iptables -t nat -D PREROUTING -j "$REDIRECT_CHAIN" 2>/dev/null; do :; done

remove_prerouting_rule() {
  while iptables -t mangle -D PREROUTING "$@" 2>/dev/null; do :; done
}
remove_nat_prerouting_rule() {
  while iptables -t nat -D PREROUTING "$@" 2>/dev/null; do :; done
}
remove_input_rule() {
  while iptables -D INPUT "$@" 2>/dev/null; do :; done
}
remove_forward_rule() {
  while iptables -t mangle -D FORWARD "$@" 2>/dev/null; do :; done
}
remove_prerouting_rule -s "$VPN_SUBNET" -j ACCEPT
remove_prerouting_rule -s "$VPN_SUBNET" -p udp --dport 53 -j ACCEPT
remove_prerouting_rule -s "$VPN_SUBNET" -p tcp --dport 53 -j ACCEPT
remove_nat_prerouting_rule -s "$VPN_SUBNET" -p tcp -j REDIRECT --to-ports "$TPROXY_PORT"
remove_input_rule -s "$VPN_SUBNET" -j ACCEPT
remove_input_rule -s "$VPN_SUBNET" -d "$VPN_GATEWAY" -p udp --dport 53 -j ACCEPT
remove_input_rule -s "$VPN_SUBNET" -d "$VPN_GATEWAY" -p tcp --dport 53 -j ACCEPT
remove_input_rule -s "$VPN_SUBNET" -p tcp --dport "$TPROXY_PORT" -j ACCEPT
remove_input_rule -s "$VPN_SUBNET" -m mark --mark ${TPROXY_MARK}/0xffffffff -j ACCEPT
remove_forward_rule -s "$VPN_SUBNET" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
remove_forward_rule -d "$VPN_SUBNET" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -S FORWARD 2>/dev/null \
  | grep -- "vpnproxi user=" \
  | sed 's/^-A/-D/' \
  | while IFS= read -r rule; do iptables -t mangle $rule 2>/dev/null || true; done \
  || true
iptables -t mangle -A "$FWD_CHAIN" -j RETURN
iptables -t mangle -S PREROUTING 2>/dev/null \
  | grep -- "-j TPROXY" \
  | grep -- "--on-port ${TPROXY_PORT}" \
  | sed 's/^-A/-D/' \
  | while IFS= read -r rule; do iptables -t mangle $rule 2>/dev/null || true; done \
  || true

if command -v ipset >/dev/null 2>&1; then
  ipset destroy "$PROXY_SET_NEXT" 2>/dev/null || true
  ipset destroy "$DIRECT_SET_NEXT" 2>/dev/null || true
  ipset flush "$PROXY_SET" 2>/dev/null || true
  ipset flush "$DIRECT_SET" 2>/dev/null || true
  ipset destroy "$PROXY_SET" 2>/dev/null || true
  ipset destroy "$DIRECT_SET" 2>/dev/null || true
fi

if [[ "$MODE" == "direct" ]]; then
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -j RETURN
  iptables -t nat -A "$REDIRECT_CHAIN" -s "$VPN_SUBNET" -j RETURN
else
  iptables -I INPUT 1 -s "$VPN_SUBNET" -d "$VPN_GATEWAY" -p udp --dport 53 -j ACCEPT
  iptables -I INPUT 2 -s "$VPN_SUBNET" -d "$VPN_GATEWAY" -p tcp --dport 53 -j ACCEPT
  iptables -I INPUT 1 -s "$VPN_SUBNET" -m mark --mark ${TPROXY_MARK}/0xffffffff -j ACCEPT
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -p udp --dport 53 -j RETURN
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -p tcp --dport 53 -j RETURN
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -m addrtype --dst-type LOCAL -j RETURN
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -d 10.0.0.0/8 -j RETURN
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -d 172.16.0.0/12 -j RETURN
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -d 192.168.0.0/16 -j RETURN
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -d 169.254.0.0/16 -j RETURN
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark ${TPROXY_MARK}/0xffffffff
  iptables -t mangle -A "$CHAIN" -s "$VPN_SUBNET" -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark ${TPROXY_MARK}/0xffffffff
fi

iptables -t nat -C POSTROUTING -s "$VPN_SUBNET" -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$WAN_IFACE" -j MASQUERADE
while iptables -D FORWARD -s "$VPN_SUBNET" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null; do :; done
while iptables -D FORWARD -d "$VPN_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
iptables -I FORWARD 1 -s "$VPN_SUBNET" -o "$WAN_IFACE" -j ACCEPT
iptables -I FORWARD 2 -d "$VPN_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t mangle -I FORWARD 1 -s "$VPN_SUBNET" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -I FORWARD 2 -d "$VPN_SUBNET" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
`, routeMode(state), state.Server.VPNSubnet, gatewayIP, fmt.Sprintf("%d", state.Server.TProxyPort), state.Server.TProxyMark, state.Server.TProxyTable, proxySetName, directSetName, dnsInboundPort)
}

func RoutingScript(state core.State) string {
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
TPROXY_MARK=%q
TPROXY_TABLE=%d
TPROXY_PRIORITY=219
LOCK_FILE=/run/vpnproxi-routing.lock

exec 9>"$LOCK_FILE"
flock -x 9
while ip rule delete fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" 2>/dev/null; do :; done
ip rule add priority "$TPROXY_PRIORITY" fwmark "$TPROXY_MARK" table "$TPROXY_TABLE"
ip route replace local 0.0.0.0/0 dev lo table "$TPROXY_TABLE"
`, state.Server.TProxyMark, state.Server.TProxyTable)
}

func DNSHealthScript(state core.State) string {
	gatewayIP := vpnGatewayIP(state.Server.VPNSubnet)
	if gatewayIP == "" {
		gatewayIP = "10.10.10.1"
	}
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
MODE=%q
DNS_SERVER="${VPNPROXI_DNS_HEALTH_SERVER:-%s}"
DNS_PORT="${VPNPROXI_DNS_HEALTH_PORT:-53}"
STATE_DIR=/run/vpnproxi
STATE_FILE="$STATE_DIR/dns-health.state"
LOCK_FILE="$STATE_DIR/dns-health.lock"
FAILURE_THRESHOLD=2
DNSMASQ_RESTART_COOLDOWN=120
XRAY_RESTART_COOLDOWN=300

[[ "$MODE" == "direct" ]] && exit 0
install -d -m 0755 "$STATE_DIR"
exec 9>"$LOCK_FILE"
flock -n 9 || exit 0

if ! command -v dig >/dev/null 2>&1; then
  logger -t vpnproxi-dns-health "dig is missing; install dnsutils"
  exit 1
fi

if ! systemctl is-active --quiet vpnproxi-dnsmasq.service; then
  logger -t vpnproxi-dns-health "resolver inactive; restarting dnsmasq"
  systemctl restart vpnproxi-dnsmasq.service
  exit 0
fi

failures=0
recovery_stage=0
last_xray_restart=0
last_dnsmasq_restart=0
if [[ -r "$STATE_FILE" ]]; then
  read -r saved_failures saved_stage saved_xray_restart saved_dnsmasq_restart < "$STATE_FILE" || true
  [[ "${saved_failures:-}" =~ ^[0-9]+$ ]] && failures="$saved_failures"
  [[ "${saved_stage:-}" =~ ^[0-9]+$ ]] && recovery_stage="$saved_stage"
  [[ "${saved_xray_restart:-}" =~ ^[0-9]+$ ]] && last_xray_restart="$saved_xray_restart"
  [[ "${saved_dnsmasq_restart:-}" =~ ^[0-9]+$ ]] && last_dnsmasq_restart="$saved_dnsmasq_restart"
fi

probe_name="vpnproxi-health-${RANDOM}-$(date +%%s).example.com"
probe_output=""
probe_ok=0
if probe_output=$(timeout 5s dig +time=3 +tries=1 "@$DNS_SERVER" -p "$DNS_PORT" "$probe_name" A +noall +comments 2>&1) \
  && grep -Eq 'status: (NOERROR|NXDOMAIN)' <<<"$probe_output"; then
  probe_ok=1
fi

# A successful uncached lookup proves that the resolver is healthy. Old queue
# saturation messages must not turn a healthy probe into a restart loop.
if (( probe_ok == 1 )); then
  printf '0 0 %%s %%s\n' "$last_xray_restart" "$last_dnsmasq_restart" > "$STATE_FILE"
  exit 0
fi

queue_saturated=0
overload_output=$(journalctl -t dnsmasq --since '30 seconds ago' \
  --grep 'Maximum number of concurrent DNS queries reached' -n 1 --output=cat --no-pager 2>/dev/null || true)
[[ -n "$overload_output" ]] && queue_saturated=1

failures=$((failures + 1))
printf '%%s %%s %%s %%s\n' "$failures" "$recovery_stage" "$last_xray_restart" "$last_dnsmasq_restart" > "$STATE_FILE"
logger -t vpnproxi-dns-health "unhealthy count=$failures probe_ok=$probe_ok queue_saturated=$queue_saturated server=$DNS_SERVER port=$DNS_PORT"
if (( failures < FAILURE_THRESHOLD )); then
  exit 0
fi

now=$(date +%%s)
if (( now - last_dnsmasq_restart < DNSMASQ_RESTART_COOLDOWN )); then
  logger -t vpnproxi-dns-health "resolver recovery cooling down; no restart"
  exit 0
fi
if (( recovery_stage > 0 && now - last_xray_restart >= XRAY_RESTART_COOLDOWN )); then
  logger -t vpnproxi-dns-health "persistent DNS failure; restarting Xray and dnsmasq"
  systemctl restart xray.service
  last_xray_restart="$now"
else
  logger -t vpnproxi-dns-health "DNS failure threshold reached; restarting dnsmasq"
fi
systemctl restart vpnproxi-dnsmasq.service
last_dnsmasq_restart="$now"
printf '0 1 %%s %%s\n' "$last_xray_restart" "$last_dnsmasq_restart" > "$STATE_FILE"
`, routeMode(state), gatewayIP)
}

func GeodataScript(state core.State) string {
	downloadXrayDat := "0"
	if requiresXrayGeodata(state) {
		downloadXrayDat = "1"
	}
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
SHARE_DIR=%q
DOWNLOAD_XRAY_DAT=%q
mkdir -p "$SHARE_DIR"
rm -f "$SHARE_DIR/ru-blocked.txt" "$SHARE_DIR/ru-blocked-community.txt" "$SHARE_DIR/telegram.txt" "$SHARE_DIR/ru-blocked-all.txt"
tmp_geoip=$(mktemp)
tmp_geosite=$(mktemp)
cleanup(){ rm -f "$tmp_geoip" "$tmp_geosite"; }
trap cleanup EXIT
CURL_FLAGS=(--fail --location --silent --show-error --connect-timeout 30 --max-time 300 --retry 3 --retry-delay 3)
LIST_MAX_AGE_SECONDS=$((20 * 60 * 60))
is_fresh() {
  local path="$1"
  local now
  local mtime
  [[ -r "$path" ]] || return 1
  now=$(date +%%s)
  mtime=$(stat -c %%Y "$path" 2>/dev/null || echo 0)
  [[ "$mtime" =~ ^[0-9]+$ ]] || return 1
  (( now >= mtime && now - mtime < LIST_MAX_AGE_SECONDS ))
}
if [[ "$DOWNLOAD_XRAY_DAT" == "1" ]]; then
  if ! is_fresh "$SHARE_DIR/geoip.dat" || ! is_fresh "$SHARE_DIR/geosite.dat"; then
    curl "${CURL_FLAGS[@]}" -o "$tmp_geoip" "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat"
    curl "${CURL_FLAGS[@]}" -o "$tmp_geosite" "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
    install -m 0644 "$tmp_geoip" "$SHARE_DIR/geoip.dat"
    install -m 0644 "$tmp_geosite" "$SHARE_DIR/geosite.dat"
    systemctl restart xray 2>/dev/null || true
  fi
fi
`, state.Server.GeodataDir, downloadXrayDat)
}

func routeMode(state core.State) string {
	if state.Routes.Mode == "" {
		return "direct"
	}
	return state.Routes.Mode
}

func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p))
	}
	return strings.Join(parts, ",")
}

func withOutboundMark(stream map[string]any) map[string]any {
	next := make(map[string]any, len(stream)+1)
	for k, v := range stream {
		next[k] = v
	}
	sockopt, _ := next["sockopt"].(map[string]any)
	if sockopt == nil {
		sockopt = map[string]any{}
	}
	sockopt["mark"] = 2
	next["sockopt"] = sockopt
	return next
}

func vpnDNSServers(state core.State) []string {
	if routeMode(state) == "direct" {
		return state.Server.VPNDNSServers
	}
	if gateway := vpnGatewayIP(state.Server.VPNSubnet); gateway != "" {
		return []string{gateway}
	}
	return state.Server.VPNDNSServers
}

func vpnGatewayIP(cidr string) string {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	gateway := make(net.IP, len(ip))
	copy(gateway, ip)
	gateway[3]++
	if !ipNet.Contains(gateway) {
		return ""
	}
	return gateway.String()
}

func vpnPoolAddrs(cidr string) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	networkIP := ipNet.IP.To4()
	if networkIP == nil {
		return cidr
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 0 || ones > 30 {
		return cidr
	}
	size := uint64(1) << uint(32-ones)
	network := uint64(binary.BigEndian.Uint32(networkIP))
	first := network + 2
	last := network + size - 2
	if first > last || last > uint64(^uint32(0)) {
		return cidr
	}
	if first == last {
		return ipv4FromUint32(uint32(first))
	}
	return fmt.Sprintf("%s-%s", ipv4FromUint32(uint32(first)), ipv4FromUint32(uint32(last)))
}

func ipv4FromUint32(value uint32) string {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return net.IP(raw[:]).String()
}

func requiresXrayGeodata(state core.State) bool {
	if routeMode(state) == "direct" {
		return false
	}
	if state.Routes.UseRunetGeodata {
		return true
	}
	for _, values := range [][]string{
		state.Routes.ProxyDomains,
		state.Routes.DirectDomains,
		state.Routes.ProxyIPs,
		state.Routes.DirectIPs,
	} {
		for _, value := range values {
			value = strings.ToLower(strings.TrimSpace(value))
			if strings.HasPrefix(value, "geosite:") || strings.HasPrefix(value, "geoip:") {
				return true
			}
		}
	}
	return false
}
