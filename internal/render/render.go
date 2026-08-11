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
install -d -m 0755 /run/vpnproxi
exec 8>/run/vpnproxi/dns-health.lock
flock -x 8
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
  primary_template_next=$(mktemp /usr/local/etc/vpnproxi/.dns-upstreams-primary.XXXXXX)
  cat >"$primary_template_next" <<DNSMASQ_PRIMARY
server=127.0.0.1#%d
DNSMASQ_PRIMARY
  chmod 0644 "$primary_template_next"
  mv -f "$primary_template_next" /usr/local/etc/vpnproxi/dns-upstreams-primary.conf
  cloudflare_template_next=$(mktemp /usr/local/etc/vpnproxi/.dns-upstreams-cloudflare.XXXXXX)
  cat >"$cloudflare_template_next" <<'DNSMASQ_FALLBACK_CLOUDFLARE'
server=1.1.1.1#53
DNSMASQ_FALLBACK_CLOUDFLARE
  chmod 0644 "$cloudflare_template_next"
  mv -f "$cloudflare_template_next" /usr/local/etc/vpnproxi/dns-upstreams-fallback-cloudflare.conf
  google_template_next=$(mktemp /usr/local/etc/vpnproxi/.dns-upstreams-google.XXXXXX)
  cat >"$google_template_next" <<'DNSMASQ_FALLBACK_GOOGLE'
server=8.8.8.8#53
DNSMASQ_FALLBACK_GOOGLE
  chmod 0644 "$google_template_next"
  mv -f "$google_template_next" /usr/local/etc/vpnproxi/dns-upstreams-fallback-google.conf
  initial_upstream_file=/usr/local/etc/vpnproxi/dns-upstreams-primary.conf
  initial_upstream_mode=primary
  initial_upstream_applied=primary
  initial_primary_failures=0
  initial_all_unavailable=0
  probe_initial_resolver() {
    local initial_server="$1"
    local initial_port="$2"
    local initial_label="$3"
    local initial_probe
    local initial_query_type
    for initial_query_type in A TXT; do
      initial_probe="vpnproxi-apply-${initial_label}-${initial_query_type}-${RANDOM}-$(date +%%s).example.com"
      if ! timeout 4s dig +time=3 +tries=1 "@$initial_server" -p "$initial_port" \
        "$initial_probe" "$initial_query_type" +noall +comments 2>/dev/null \
        | grep -Eq 'status: (NOERROR|NXDOMAIN)'; then
        return 1
      fi
    done
    return 0
  }
  if ! probe_initial_resolver 127.0.0.1 %d primary; then
    initial_primary_failures=1
    if probe_initial_resolver 1.1.1.1 53 cloudflare; then
      initial_upstream_file=/usr/local/etc/vpnproxi/dns-upstreams-fallback-cloudflare.conf
      initial_upstream_mode=fallback
      initial_upstream_applied=cloudflare
      initial_primary_failures=0
    elif probe_initial_resolver 8.8.8.8 53 google; then
      initial_upstream_file=/usr/local/etc/vpnproxi/dns-upstreams-fallback-google.conf
      initial_upstream_mode=fallback
      initial_upstream_applied=google
      initial_primary_failures=0
    else
      initial_all_unavailable=1
    fi
  fi
  install -m 0644 "$initial_upstream_file" /run/vpnproxi/dns-upstreams.conf
  printf '%%s\n' "$initial_upstream_mode" >/run/vpnproxi/dns-upstream-mode
  printf '%%s\n' "$initial_upstream_applied" >/run/vpnproxi/dns-upstream-applied
  rm -f /run/vpnproxi/dns-health.state /run/vpnproxi/dns-upstream.state \
    /run/vpnproxi/dns-primary-degraded /run/vpnproxi/dns-fallback-unavailable
  if [[ "$initial_upstream_mode" == "fallback" ]]; then
    : >/run/vpnproxi/dns-primary-degraded
  elif (( initial_all_unavailable == 1 )); then
    : >/run/vpnproxi/dns-primary-degraded
    : >/run/vpnproxi/dns-fallback-unavailable
  fi
  printf '%%s %%s 0 %%s\n' "$initial_upstream_mode" "$initial_primary_failures" "$(date +%%s)" >/run/vpnproxi/dns-upstream.state
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
servers-file=/run/vpnproxi/dns-upstreams.conf
DNSMASQ
  cat >/etc/systemd/system/vpnproxi-dnsmasq.service <<'DNSMASQ_SERVICE'
[Unit]
Description=VPNproxi local DNS cache
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/sh -c 'until /usr/sbin/ip -4 -o addr show dev lo | /usr/bin/grep -q " %s/32 "; do /usr/bin/sleep 1; done'
ExecStartPre=/bin/sh -c 'install -d -m 0755 /run/vpnproxi; test -s /run/vpnproxi/dns-upstreams.conf || install -m 0644 /usr/local/etc/vpnproxi/dns-upstreams-primary.conf /run/vpnproxi/dns-upstreams.conf'
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/usr/local/etc/vpnproxi/dnsmasq.conf --pid-file=/run/vpnproxi-dnsmasq.pid
Restart=on-failure
RestartSec=2
TimeoutStartSec=75

[Install]
WantedBy=multi-user.target
DNSMASQ_SERVICE
  systemctl daemon-reload
  systemctl enable vpnproxi-dnsmasq >/dev/null 2>&1 || true
  systemctl restart vpnproxi-dnsmasq
else
  systemctl stop vpnproxi-dnsmasq 2>/dev/null || true
  rm -f /usr/local/etc/vpnproxi/dnsmasq-routes.conf /usr/local/etc/vpnproxi/dnsmasq-direct-domains.txt \
    /usr/local/etc/vpnproxi/dns-upstreams-primary.conf \
    /usr/local/etc/vpnproxi/dns-upstreams-fallback-cloudflare.conf \
    /usr/local/etc/vpnproxi/dns-upstreams-fallback-google.conf \
    /run/vpnproxi/dns-upstreams.conf /run/vpnproxi/dns-upstream-mode /run/vpnproxi/dns-upstream-applied \
    /run/vpnproxi/dns-upstream.state \
    /run/vpnproxi/dns-primary-degraded /run/vpnproxi/dns-fallback-unavailable
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
`, routeMode(state), state.Server.VPNSubnet, gatewayIP, fmt.Sprintf("%d", state.Server.TProxyPort), state.Server.TProxyMark, state.Server.TProxyTable, proxySetName, directSetName, dnsInboundPort, dnsInboundPort, gatewayIP)
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
PRIMARY_DNS_SERVER="${VPNPROXI_DNS_PRIMARY_SERVER:-127.0.0.1}"
PRIMARY_DNS_PORT="${VPNPROXI_DNS_PRIMARY_PORT:-%d}"
STATE_DIR=/run/vpnproxi
STATE_FILE="$STATE_DIR/dns-health.state"
LOCK_FILE="$STATE_DIR/dns-health.lock"
PRIMARY_DEGRADED_FILE="$STATE_DIR/dns-primary-degraded"
UPSTREAM_FILE="$STATE_DIR/dns-upstreams.conf"
UPSTREAM_MODE_FILE="$STATE_DIR/dns-upstream-mode"
UPSTREAM_APPLIED_FILE="$STATE_DIR/dns-upstream-applied"
UPSTREAM_STATE_FILE="$STATE_DIR/dns-upstream.state"
PRIMARY_UPSTREAM_FILE=/usr/local/etc/vpnproxi/dns-upstreams-primary.conf
CLOUDFLARE_UPSTREAM_FILE=/usr/local/etc/vpnproxi/dns-upstreams-fallback-cloudflare.conf
GOOGLE_UPSTREAM_FILE=/usr/local/etc/vpnproxi/dns-upstreams-fallback-google.conf
FALLBACK_UNAVAILABLE_FILE="$STATE_DIR/dns-fallback-unavailable"
PRIMARY_FAIL_THRESHOLD="${VPNPROXI_DNS_PRIMARY_FAIL_THRESHOLD:-2}"
RECOVERY_SUCCESS_THRESHOLD="${VPNPROXI_DNS_RECOVERY_SUCCESS_THRESHOLD:-6}"
MIN_FALLBACK_DWELL="${VPNPROXI_DNS_MIN_FALLBACK_DWELL:-120}"
FAILURE_THRESHOLD=2
DNSMASQ_RESTART_COOLDOWN=120

[[ "$MODE" == "direct" ]] && exit 0
install -d -m 0755 "$STATE_DIR"
exec 9>"$LOCK_FILE"
flock -n 9 || exit 0

if ! command -v dig >/dev/null 2>&1; then
  logger -t vpnproxi-dns-health "dig is missing; install dnsutils"
  exit 1
fi

activate_upstreams() {
  local source_file="$1"
  local desired_mode="$2"
  local tmp_file
  local applied_mode
  local desired_applied
  if [[ ! -s "$source_file" ]]; then
    logger -t vpnproxi-dns-health "missing DNS upstream template: $source_file"
    return 1
  fi
  desired_applied="$desired_mode"
  [[ "$source_file" == "$CLOUDFLARE_UPSTREAM_FILE" ]] && desired_applied=cloudflare
  [[ "$source_file" == "$GOOGLE_UPSTREAM_FILE" ]] && desired_applied=google
  applied_mode=$(cat "$UPSTREAM_APPLIED_FILE" 2>/dev/null || true)
  if cmp -s "$source_file" "$UPSTREAM_FILE" && [[ "$applied_mode" == "$desired_applied" ]]; then
    return 0
  fi
  if ! cmp -s "$source_file" "$UPSTREAM_FILE"; then
    tmp_file=$(mktemp "$STATE_DIR/dns-upstreams.XXXXXX")
    install -m 0644 "$source_file" "$tmp_file"
    mv -f "$tmp_file" "$UPSTREAM_FILE"
  fi
  systemctl kill --kill-who=main --signal=HUP vpnproxi-dnsmasq.service
  printf '%%s\n' "$desired_applied" > "$UPSTREAM_APPLIED_FILE"
  printf '%%s\n' "$desired_mode" > "$UPSTREAM_MODE_FILE"
  sleep 0.2
}

write_upstream_state() {
  local tmp_file
  tmp_file=$(mktemp "$STATE_DIR/dns-upstream-state.XXXXXX")
  printf '%%s %%s %%s %%s\n' "$upstream_mode" "$primary_failures" "$recovery_successes" "$last_switch" > "$tmp_file"
  chmod 0644 "$tmp_file"
  mv -f "$tmp_file" "$UPSTREAM_STATE_FILE"
  printf '%%s\n' "$upstream_mode" > "$UPSTREAM_MODE_FILE"
}

repair_upstream_template() {
  local path="$1"
  local expected="$2"
  local tmp_file
  if [[ -r "$path" && $(wc -l < "$path") -eq 1 ]] && grep -qxF "$expected" "$path"; then
    return 0
  fi
  install -d -m 0755 "$(dirname "$path")"
  tmp_file=$(mktemp "$(dirname "$path")/.dns-upstream-template.XXXXXX")
  printf '%%s\n' "$expected" > "$tmp_file"
  chmod 0644 "$tmp_file"
  mv -f "$tmp_file" "$path"
  logger -t vpnproxi-dns-health "repaired DNS upstream template: $path"
}

repair_upstream_templates() {
  repair_upstream_template "$PRIMARY_UPSTREAM_FILE" 'server=127.0.0.1#%d'
  repair_upstream_template "$CLOUDFLARE_UPSTREAM_FILE" 'server=1.1.1.1#53'
  repair_upstream_template "$GOOGLE_UPSTREAM_FILE" 'server=8.8.8.8#53'
}

select_healthy_fallback() {
  selected_fallback_file=""
  selected_fallback_name=""
  if probe_resolver 1.1.1.1 53 fallback-cloudflare; then
    selected_fallback_file="$CLOUDFLARE_UPSTREAM_FILE"
    selected_fallback_name=cloudflare
    return 0
  fi
  if probe_resolver 8.8.8.8 53 fallback-google; then
    selected_fallback_file="$GOOGLE_UPSTREAM_FILE"
    selected_fallback_name=google
    return 0
  fi
  return 1
}

probe_resolver() {
  local server="$1"
  local port="$2"
  local label="$3"
  local probe_name
  local output
  local query_type
  for query_type in A TXT; do
    probe_name="vpnproxi-${label}-${query_type}-${RANDOM}-$(date +%%s).example.com"
    output=""
    if ! output=$(timeout 4s dig +time=3 +tries=1 "@$server" -p "$port" "$probe_name" "$query_type" +noall +comments 2>&1) \
      || ! grep -Eq 'status: (NOERROR|NXDOMAIN)' <<<"$output"; then
      return 1
    fi
  done
  return 0
}

for value in "$PRIMARY_FAIL_THRESHOLD" "$RECOVERY_SUCCESS_THRESHOLD" "$MIN_FALLBACK_DWELL"; do
  [[ "$value" =~ ^[0-9]+$ ]] || { logger -t vpnproxi-dns-health "invalid DNS failover threshold"; exit 1; }
done
(( 10#$PRIMARY_FAIL_THRESHOLD > 0 && 10#$RECOVERY_SUCCESS_THRESHOLD > 0 && 10#$MIN_FALLBACK_DWELL > 0 )) \
  || { logger -t vpnproxi-dns-health "DNS failover thresholds and dwell must be greater than zero"; exit 1; }
PRIMARY_FAIL_THRESHOLD=$((10#$PRIMARY_FAIL_THRESHOLD))
RECOVERY_SUCCESS_THRESHOLD=$((10#$RECOVERY_SUCCESS_THRESHOLD))
MIN_FALLBACK_DWELL=$((10#$MIN_FALLBACK_DWELL))

repair_upstream_templates

failures=0
last_dnsmasq_restart=0
if [[ -r "$STATE_FILE" ]]; then
  read -r saved_failures saved_stage saved_xray_restart saved_dnsmasq_restart < "$STATE_FILE" || true
  [[ "${saved_failures:-}" =~ ^[0-9]+$ ]] && failures="$saved_failures"
  [[ "${saved_dnsmasq_restart:-}" =~ ^[0-9]+$ ]] && last_dnsmasq_restart="$saved_dnsmasq_restart"
fi

if ! systemctl is-active --quiet vpnproxi-dnsmasq.service; then
  now=$(date +%%s)
  if ! cmp -s "$PRIMARY_UPSTREAM_FILE" "$UPSTREAM_FILE" \
    && ! cmp -s "$CLOUDFLARE_UPSTREAM_FILE" "$UPSTREAM_FILE" \
    && ! cmp -s "$GOOGLE_UPSTREAM_FILE" "$UPSTREAM_FILE"; then
    install -m 0644 "$PRIMARY_UPSTREAM_FILE" "$UPSTREAM_FILE"
    rm -f "$UPSTREAM_STATE_FILE" "$PRIMARY_DEGRADED_FILE" "$FALLBACK_UNAVAILABLE_FILE"
  fi
  if (( now - last_dnsmasq_restart < DNSMASQ_RESTART_COOLDOWN )); then
    exit 0
  fi
  printf '0 0 0 %%s\n' "$now" > "$STATE_FILE"
  logger -t vpnproxi-dns-health "resolver inactive; restarting dnsmasq"
  systemctl restart vpnproxi-dnsmasq.service
  if cmp -s "$PRIMARY_UPSTREAM_FILE" "$UPSTREAM_FILE"; then
    printf 'primary\n' > "$UPSTREAM_MODE_FILE"
    printf 'primary\n' > "$UPSTREAM_APPLIED_FILE"
  elif cmp -s "$CLOUDFLARE_UPSTREAM_FILE" "$UPSTREAM_FILE"; then
    printf 'fallback\n' > "$UPSTREAM_MODE_FILE"
    printf 'cloudflare\n' > "$UPSTREAM_APPLIED_FILE"
  else
    printf 'fallback\n' > "$UPSTREAM_MODE_FILE"
    printf 'google\n' > "$UPSTREAM_APPLIED_FILE"
  fi
  exit 0
fi

# A silent strict-order upstream is not a reliable fallback mechanism in
# dnsmasq. Keep exactly one upstream class active, switch its servers-file
# explicitly, and use hysteresis so a transient probe cannot flush the cache
# repeatedly. Never restart the shared Xray datapath here.
upstream_mode=primary
active_upstream=unknown
active_upstream_file=""
if cmp -s "$PRIMARY_UPSTREAM_FILE" "$UPSTREAM_FILE"; then
  active_upstream=primary
  active_upstream_file="$PRIMARY_UPSTREAM_FILE"
elif cmp -s "$CLOUDFLARE_UPSTREAM_FILE" "$UPSTREAM_FILE"; then
  active_upstream=cloudflare
  active_upstream_file="$CLOUDFLARE_UPSTREAM_FILE"
  upstream_mode=fallback
elif cmp -s "$GOOGLE_UPSTREAM_FILE" "$UPSTREAM_FILE"; then
  active_upstream=google
  active_upstream_file="$GOOGLE_UPSTREAM_FILE"
  upstream_mode=fallback
fi
if [[ -n "$active_upstream_file" ]]; then
  activate_upstreams "$active_upstream_file" "$upstream_mode"
fi
primary_failures=0
recovery_successes=0
last_switch=0
if [[ -r "$UPSTREAM_STATE_FILE" ]]; then
  read -r saved_mode saved_primary_failures saved_recovery_successes saved_last_switch < "$UPSTREAM_STATE_FILE" || true
  if [[ "${saved_mode:-}" == "$upstream_mode" \
    && "${saved_primary_failures:-}" =~ ^[0-9]+$ \
    && "${saved_recovery_successes:-}" =~ ^[0-9]+$ \
    && "${saved_last_switch:-}" =~ ^[0-9]+$ ]]; then
    primary_failures="$saved_primary_failures"
    recovery_successes="$saved_recovery_successes"
    last_switch="$saved_last_switch"
  fi
fi

now=$(date +%%s)
primary_probe_ok=0
probe_resolver "$PRIMARY_DNS_SERVER" "$PRIMARY_DNS_PORT" primary && primary_probe_ok=1

if [[ "$active_upstream" == "unknown" ]]; then
  if (( primary_probe_ok == 1 )); then
    activate_upstreams "$PRIMARY_UPSTREAM_FILE" primary
    upstream_mode=primary
    active_upstream=primary
  elif select_healthy_fallback; then
    activate_upstreams "$selected_fallback_file" fallback
    upstream_mode=fallback
    active_upstream="$selected_fallback_name"
    last_switch="$now"
    : > "$PRIMARY_DEGRADED_FILE"
    logger -t vpnproxi-dns-health "repaired invalid DNS upstream file with healthy $selected_fallback_name fallback"
  else
    activate_upstreams "$PRIMARY_UPSTREAM_FILE" primary
    upstream_mode=primary
    active_upstream=primary
    : > "$PRIMARY_DEGRADED_FILE"
    : > "$FALLBACK_UNAVAILABLE_FILE"
    logger -t vpnproxi-dns-health "repaired invalid DNS upstream file; no resolver currently answers"
  fi
  primary_failures=0
  recovery_successes=0
fi

if [[ "$upstream_mode" == "primary" ]]; then
  recovery_successes=0
  if (( primary_probe_ok == 1 )); then
    primary_failures=0
    rm -f "$PRIMARY_DEGRADED_FILE" "$FALLBACK_UNAVAILABLE_FILE"
  else
    primary_failures=$((primary_failures + 1))
    : > "$PRIMARY_DEGRADED_FILE"
  fi
  if (( primary_failures >= PRIMARY_FAIL_THRESHOLD )); then
    if select_healthy_fallback; then
      rm -f "$FALLBACK_UNAVAILABLE_FILE"
      activate_upstreams "$selected_fallback_file" fallback
      upstream_mode=fallback
      active_upstream="$selected_fallback_name"
      primary_failures=0
      recovery_successes=0
      last_switch="$now"
      : > "$PRIMARY_DEGRADED_FILE"
      logger -t vpnproxi-dns-health "encrypted DNS primary degraded; activated $selected_fallback_name DNS fallback"
    elif [[ ! -e "$FALLBACK_UNAVAILABLE_FILE" ]]; then
      : > "$FALLBACK_UNAVAILABLE_FILE"
      logger -t vpnproxi-dns-health "encrypted DNS primary and direct fallbacks are unavailable"
    fi
  fi
else
  primary_failures=0
  if (( primary_probe_ok == 1 )); then
    recovery_successes=$((recovery_successes + 1))
  else
    recovery_successes=0
  fi
  if (( recovery_successes >= RECOVERY_SUCCESS_THRESHOLD \
    && now >= last_switch \
    && now - last_switch >= MIN_FALLBACK_DWELL )); then
    activate_upstreams "$PRIMARY_UPSTREAM_FILE" primary
    upstream_mode=primary
    primary_failures=0
    recovery_successes=0
    last_switch="$now"
    rm -f "$PRIMARY_DEGRADED_FILE" "$FALLBACK_UNAVAILABLE_FILE"
    logger -t vpnproxi-dns-health "encrypted DNS primary recovered; deactivated direct fallback"
  fi
fi
write_upstream_state

# Probe the client path after any upstream transition. A successful lookup
# proves that dnsmasq is healthy. Old queue messages must not create a loop.
probe_ok=0
probe_resolver "$DNS_SERVER" "$DNS_PORT" client && probe_ok=1

# If one public fallback fails while the primary is still unavailable, test
# and activate the other one before considering a service restart.
if (( probe_ok == 0 && primary_probe_ok == 0 )) && [[ "$upstream_mode" == "fallback" ]]; then
  alternate_file=""
  alternate_name=""
  if [[ "$active_upstream" == "cloudflare" ]] && probe_resolver 8.8.8.8 53 alternate-google; then
    alternate_file="$GOOGLE_UPSTREAM_FILE"
    alternate_name=google
  elif [[ "$active_upstream" == "google" ]] && probe_resolver 1.1.1.1 53 alternate-cloudflare; then
    alternate_file="$CLOUDFLARE_UPSTREAM_FILE"
    alternate_name=cloudflare
  fi
  if [[ -n "$alternate_file" ]]; then
    activate_upstreams "$alternate_file" fallback
    active_upstream="$alternate_name"
    last_switch=$(date +%%s)
    recovery_successes=0
    write_upstream_state
    rm -f "$FALLBACK_UNAVAILABLE_FILE"
    logger -t vpnproxi-dns-health "active DNS fallback failed; switched to $alternate_name"
    probe_resolver "$DNS_SERVER" "$DNS_PORT" client-alternate && probe_ok=1
  elif [[ ! -e "$FALLBACK_UNAVAILABLE_FILE" ]]; then
    : > "$FALLBACK_UNAVAILABLE_FILE"
    logger -t vpnproxi-dns-health "encrypted DNS primary and direct fallbacks are unavailable"
  fi
fi

# If the active direct fallback fails while the encrypted primary is already
# healthy, recover immediately instead of waiting for the normal dwell time.
if (( probe_ok == 0 && primary_probe_ok == 1 )) && [[ "$upstream_mode" == "fallback" ]]; then
  activate_upstreams "$PRIMARY_UPSTREAM_FILE" primary
  upstream_mode=primary
  active_upstream=primary
  primary_failures=0
  recovery_successes=0
  last_switch=$(date +%%s)
  rm -f "$PRIMARY_DEGRADED_FILE" "$FALLBACK_UNAVAILABLE_FILE"
  write_upstream_state
  logger -t vpnproxi-dns-health "direct DNS fallback failed; restored healthy encrypted primary"
  probe_resolver "$DNS_SERVER" "$DNS_PORT" client-retry && probe_ok=1
fi

# Reconcile persistent UI markers from the live upstream state. This keeps a
# previous all-resolvers-down incident from remaining visible after recovery.
if (( probe_ok == 1 )); then
  if [[ "$upstream_mode" == "primary" ]] && (( primary_probe_ok == 1 )); then
    rm -f "$PRIMARY_DEGRADED_FILE" "$FALLBACK_UNAVAILABLE_FILE"
  elif [[ "$upstream_mode" == "fallback" ]]; then
    : > "$PRIMARY_DEGRADED_FILE"
    rm -f "$FALLBACK_UNAVAILABLE_FILE"
  fi
fi
if (( probe_ok == 1 )); then
  printf '0 0 0 %%s\n' "$last_dnsmasq_restart" > "$STATE_FILE"
  exit 0
fi

queue_saturated=0
overload_output=$(journalctl -t dnsmasq --since '30 seconds ago' \
  --grep 'Maximum number of concurrent DNS queries reached' -n 1 --output=cat --no-pager 2>/dev/null || true)
[[ -n "$overload_output" ]] && queue_saturated=1

failures=$((failures + 1))
printf '%%s 0 0 %%s\n' "$failures" "$last_dnsmasq_restart" > "$STATE_FILE"
logger -t vpnproxi-dns-health "client resolver unhealthy count=$failures queue_saturated=$queue_saturated server=$DNS_SERVER port=$DNS_PORT"
if (( failures < FAILURE_THRESHOLD )); then
  exit 0
fi

now=$(date +%%s)
if (( now - last_dnsmasq_restart < DNSMASQ_RESTART_COOLDOWN )); then
  logger -t vpnproxi-dns-health "resolver recovery cooling down; no restart"
  exit 0
fi
logger -t vpnproxi-dns-health "DNS failure threshold reached; restarting dnsmasq only"
systemctl restart vpnproxi-dnsmasq.service
last_dnsmasq_restart="$now"
printf '0 0 0 %%s\n' "$last_dnsmasq_restart" > "$STATE_FILE"
`, routeMode(state), gatewayIP, dnsInboundPort, dnsInboundPort)
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
