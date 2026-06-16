package link

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type ProbeResult struct {
	OK         bool   `json:"ok"`
	Network    string `json:"network"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	ResolvedIP string `json:"resolvedIp,omitempty"`
	LatencyMS  int64  `json:"latencyMs,omitempty"`
	Error      string `json:"error,omitempty"`
}

func Probe(out *Outbound, timeout time.Duration) ProbeResult {
	network, host, port, err := ProbeTarget(out)
	if err != nil {
		return ProbeResult{Network: network, Host: host, Port: port, Error: err.Error()}
	}
	result := ProbeResult{Network: network, Host: host, Port: port}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		result.Error = fmt.Sprintf("DNS lookup failed: %v", err)
		return result
	}
	if len(ips) > 0 {
		result.ResolvedIP = ips[0].IP.String()
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	_ = conn.Close()
	result.OK = true
	result.LatencyMS = time.Since(start).Milliseconds()
	return result
}

func ProbeTarget(out *Outbound) (network, host string, port int, err error) {
	if out == nil {
		return "", "", 0, fmt.Errorf("external route is empty")
	}
	switch out.Protocol {
	case "vmess", "vless":
		server, probeErr := firstServer(out.Settings, "vnext")
		if probeErr != nil {
			return "tcp", "", 0, probeErr
		}
		return "tcp", getString(server, "address", ""), number(server["port"], 443), nil
	case "trojan", "shadowsocks":
		server, probeErr := firstServer(out.Settings, "servers")
		if probeErr != nil {
			return "tcp", "", 0, probeErr
		}
		return "tcp", getString(server, "address", ""), number(server["port"], 443), nil
	case "hysteria":
		return "udp", getString(out.Settings, "address", ""), number(out.Settings["port"], 443), nil
	case "wireguard":
		peers, ok := out.Settings["peers"].([]any)
		if !ok || len(peers) == 0 {
			return "udp", "", 0, fmt.Errorf("wireguard peer endpoint is missing")
		}
		peer, ok := peers[0].(map[string]any)
		if !ok {
			return "udp", "", 0, fmt.Errorf("wireguard peer endpoint is invalid")
		}
		endpoint := strings.TrimSpace(getString(peer, "endpoint", ""))
		if endpoint == "" {
			return "udp", "", 0, fmt.Errorf("wireguard peer endpoint is empty")
		}
		host, port := splitHostPort(endpoint, 51820)
		return "udp", host, port, nil
	default:
		return "", "", 0, fmt.Errorf("route check is not supported for protocol %q", out.Protocol)
	}
}

func firstServer(settings map[string]any, key string) (map[string]any, error) {
	servers, ok := settings[key].([]any)
	if !ok || len(servers) == 0 {
		return nil, fmt.Errorf("%s server address is missing", key)
	}
	server, ok := servers[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s server entry is invalid", key)
	}
	host := strings.TrimSpace(getString(server, "address", ""))
	if host == "" {
		return nil, fmt.Errorf("%s server address is empty", key)
	}
	return server, nil
}
