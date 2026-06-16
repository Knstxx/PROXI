package link

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type Outbound struct {
	Protocol       string         `json:"protocol"`
	Tag            string         `json:"tag"`
	Settings       map[string]any `json:"settings"`
	StreamSettings map[string]any `json:"streamSettings,omitempty"`
	Identity       string         `json:"identity"`
	RawLink        string         `json:"rawLink,omitempty"`
}

func Parse(raw string) (*Outbound, error) {
	raw = strings.TrimSpace(raw)
	var (
		out *Outbound
		err error
	)
	switch {
	case strings.HasPrefix(raw, "vmess://"):
		out, err = parseVMess(raw)
	case strings.HasPrefix(raw, "vless://"):
		out, err = parseVLESS(raw)
	case strings.HasPrefix(raw, "trojan://"):
		out, err = parseTrojan(raw)
	case strings.HasPrefix(raw, "ss://"):
		out, err = parseShadowsocks(raw)
	case strings.HasPrefix(raw, "hysteria2://"), strings.HasPrefix(raw, "hy2://"):
		out, err = parseHysteria2(raw)
	case strings.HasPrefix(raw, "wireguard://"), strings.HasPrefix(raw, "wg://"):
		out, err = parseWireGuard(raw)
	default:
		return nil, fmt.Errorf("unsupported link scheme")
	}
	if err != nil {
		return nil, err
	}
	out.RawLink = raw
	if out.Tag == "" {
		out.Tag = "proxy-primary"
	}
	return out, nil
}

func parseVMess(raw string) (*Outbound, error) {
	blob := strings.TrimPrefix(raw, "vmess://")
	decoded, err := base64DecodeFlexible(blob)
	if err != nil {
		return nil, fmt.Errorf("vmess decode: %w", err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(decoded), &body); err != nil {
		return nil, fmt.Errorf("vmess json: %w", err)
	}
	network := getString(body, "net", "tcp")
	security := "none"
	if getString(body, "tls", "") == "tls" {
		security = "tls"
	}
	stream := buildStream(network, security)
	applyVMessTransport(stream, body)
	if security == "tls" {
		tls := stream["tlsSettings"].(map[string]any)
		tls["serverName"] = getString(body, "sni", "")
		tls["fingerprint"] = getString(body, "fp", "")
		if alpn := getString(body, "alpn", ""); alpn != "" {
			tls["alpn"] = splitComma(alpn)
		}
	}
	return &Outbound{
		Protocol: "vmess",
		Tag:      getString(body, "ps", "proxy-primary"),
		Settings: map[string]any{
			"vnext": []any{map[string]any{
				"address": getString(body, "add", ""),
				"port":    number(body["port"], 443),
				"users": []any{map[string]any{
					"id":       getString(body, "id", ""),
					"security": getString(body, "scy", "auto"),
				}},
			}},
		},
		StreamSettings: stream,
		Identity:       "vmess:" + stableJSON(body, "ps"),
	}, nil
}

func parseVLESS(raw string) (*Outbound, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	network := firstNonEmpty(q.Get("type"), "tcp")
	security := firstNonEmpty(q.Get("security"), "none")
	stream := buildStream(network, security)
	applyURLTransport(stream, q)
	applyURLSecurity(stream, q)
	return &Outbound{
		Protocol: "vless",
		Tag:      decodeFragment(u.Fragment),
		Settings: map[string]any{
			"vnext": []any{map[string]any{
				"address": u.Hostname(),
				"port":    defaultPort(u.Port(), 443),
				"users": []any{map[string]any{
					"id":         u.User.Username(),
					"encryption": firstNonEmpty(q.Get("encryption"), "none"),
					"flow":       q.Get("flow"),
				}},
			}},
		},
		StreamSettings: stream,
		Identity:       "vless:" + u.User.Username() + "@" + u.Hostname() + ":" + strconv.Itoa(defaultPort(u.Port(), 443)) + "?" + q.Encode(),
	}, nil
}

func parseTrojan(raw string) (*Outbound, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	network := firstNonEmpty(q.Get("type"), "tcp")
	security := firstNonEmpty(q.Get("security"), "tls")
	stream := buildStream(network, security)
	applyURLTransport(stream, q)
	applyURLSecurity(stream, q)
	return &Outbound{
		Protocol: "trojan",
		Tag:      decodeFragment(u.Fragment),
		Settings: map[string]any{
			"servers": []any{map[string]any{
				"address":  u.Hostname(),
				"port":     defaultPort(u.Port(), 443),
				"password": u.User.Username(),
			}},
		},
		StreamSettings: stream,
		Identity:       "trojan:" + u.User.Username() + "@" + u.Hostname() + ":" + strconv.Itoa(defaultPort(u.Port(), 443)) + "?" + q.Encode(),
	}, nil
}

func parseShadowsocks(raw string) (*Outbound, error) {
	remark := ""
	if idx := strings.Index(raw, "#"); idx >= 0 {
		remark = decodeFragment(raw[idx+1:])
		raw = raw[:idx]
	}
	if idx := strings.Index(raw, "?"); idx >= 0 {
		raw = raw[:idx]
	}
	core := strings.TrimPrefix(raw, "ss://")
	var userInfo, host string
	var port int
	if at := strings.Index(core, "@"); at >= 0 {
		userInfo = core[:at]
		if decoded, err := base64DecodeFlexible(userInfo); err == nil {
			userInfo = decoded
		}
		host, port = splitHostPort(core[at+1:], 8388)
	} else {
		decoded, err := base64DecodeFlexible(core)
		if err != nil {
			return nil, err
		}
		at := strings.LastIndex(decoded, "@")
		if at < 0 {
			return nil, fmt.Errorf("bad shadowsocks link")
		}
		userInfo = decoded[:at]
		host, port = splitHostPort(decoded[at+1:], 8388)
	}
	method, password := splitOnce(userInfo, ":")
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	return &Outbound{
		Protocol: "shadowsocks",
		Tag:      remark,
		Settings: map[string]any{"servers": []any{map[string]any{
			"address": host, "port": port, "method": method, "password": password,
		}}},
		Identity: "ss:" + method + ":" + password + "@" + host + ":" + strconv.Itoa(port),
	}, nil
}

func parseHysteria2(raw string) (*Outbound, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	alpn := splitComma(q.Get("alpn"))
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	stream := map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"hysteriaSettings": map[string]any{"version": 2, "auth": u.User.Username(), "udpIdleTimeout": 60},
		"tlsSettings": map[string]any{
			"serverName": q.Get("sni"), "alpn": alpn, "fingerprint": q.Get("fp"),
			"echConfigList": q.Get("ech"), "pinnedPeerCertSha256": q.Get("pinSHA256"),
		},
	}
	return &Outbound{
		Protocol:       "hysteria",
		Tag:            decodeFragment(u.Fragment),
		Settings:       map[string]any{"address": u.Hostname(), "port": defaultPort(u.Port(), 443), "version": 2},
		StreamSettings: stream,
		Identity:       "hysteria2:" + u.User.Username() + "@" + u.Hostname() + ":" + strconv.Itoa(defaultPort(u.Port(), 443)) + "?" + q.Encode(),
	}, nil
}

func parseWireGuard(raw string) (*Outbound, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	endpoint := u.Hostname()
	if u.Port() != "" {
		endpoint += ":" + u.Port()
	}
	allowed := splitComma(firstNonEmpty(q.Get("allowedips"), q.Get("allowed_ips")))
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	address := splitComma(firstNonEmpty(q.Get("address"), q.Get("ip")))
	return &Outbound{
		Protocol: "wireguard",
		Tag:      decodeFragment(u.Fragment),
		Settings: map[string]any{
			"secretKey": u.User.Username(),
			"address":   address,
			"peers": []any{map[string]any{
				"publicKey":  firstQuery(q, "publickey", "publicKey", "public_key", "peerPublicKey"),
				"endpoint":   endpoint,
				"allowedIPs": allowed,
			}},
		},
		Identity: "wireguard:" + u.User.Username() + "@" + endpoint + "?" + q.Encode(),
	}, nil
}

func buildStream(network, security string) map[string]any {
	stream := map[string]any{"network": network, "security": security}
	switch network {
	case "ws":
		stream["wsSettings"] = map[string]any{"path": "/", "host": "", "headers": map[string]any{}}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": "", "authority": "", "multiMode": false}
	case "httpupgrade":
		stream["httpupgradeSettings"] = map[string]any{"path": "/", "host": "", "headers": map[string]any{}}
	case "xhttp":
		stream["xhttpSettings"] = map[string]any{"path": "/", "host": "", "mode": "auto", "headers": map[string]any{}}
	case "kcp":
		stream["kcpSettings"] = map[string]any{"mtu": 1350, "tti": 20, "uplinkCapacity": 5, "downlinkCapacity": 20}
	default:
		stream["tcpSettings"] = map[string]any{"header": map[string]any{"type": "none"}}
	}
	switch security {
	case "tls":
		stream["tlsSettings"] = map[string]any{"serverName": "", "alpn": []string{}, "fingerprint": ""}
	case "reality":
		stream["realitySettings"] = map[string]any{"serverName": "", "fingerprint": "chrome", "publicKey": "", "shortId": "", "spiderX": ""}
	}
	return stream
}

func applyVMessTransport(stream map[string]any, body map[string]any) {
	switch stream["network"] {
	case "ws":
		ws := stream["wsSettings"].(map[string]any)
		ws["host"] = getString(body, "host", "")
		ws["path"] = getString(body, "path", "/")
	case "grpc":
		grpc := stream["grpcSettings"].(map[string]any)
		grpc["serviceName"] = getString(body, "path", "")
		grpc["authority"] = getString(body, "authority", "")
		grpc["multiMode"] = getString(body, "type", "") == "multi"
	case "xhttp":
		xh := stream["xhttpSettings"].(map[string]any)
		xh["host"] = getString(body, "host", "")
		xh["path"] = getString(body, "path", "/")
		xh["mode"] = getString(body, "mode", "auto")
	}
}

func applyURLTransport(stream map[string]any, q url.Values) {
	host := q.Get("host")
	path := firstNonEmpty(q.Get("path"), "/")
	switch stream["network"] {
	case "ws":
		ws := stream["wsSettings"].(map[string]any)
		ws["host"] = host
		ws["path"] = path
	case "grpc":
		grpc := stream["grpcSettings"].(map[string]any)
		grpc["serviceName"] = firstNonEmpty(q.Get("serviceName"), q.Get("path"))
		grpc["authority"] = q.Get("authority")
		grpc["multiMode"] = q.Get("mode") == "multi"
	case "httpupgrade":
		hu := stream["httpupgradeSettings"].(map[string]any)
		hu["host"] = host
		hu["path"] = path
	case "xhttp":
		xh := stream["xhttpSettings"].(map[string]any)
		xh["host"] = host
		xh["path"] = path
		if mode := q.Get("mode"); mode != "" {
			xh["mode"] = mode
		}
	case "tcp":
		if q.Get("headerType") == "http" || q.Get("type") == "http" {
			stream["tcpSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": map[string]any{
				"version": "1.1", "method": "GET", "path": splitComma(path), "headers": map[string]any{"Host": splitComma(host)},
			}}}
		}
	}
}

func applyURLSecurity(stream map[string]any, q url.Values) {
	switch stream["security"] {
	case "tls":
		tls := stream["tlsSettings"].(map[string]any)
		tls["serverName"] = q.Get("sni")
		tls["fingerprint"] = q.Get("fp")
		tls["alpn"] = splitComma(q.Get("alpn"))
		tls["echConfigList"] = q.Get("ech")
		tls["pinnedPeerCertSha256"] = q.Get("pcs")
	case "reality":
		re := stream["realitySettings"].(map[string]any)
		re["serverName"] = q.Get("sni")
		re["fingerprint"] = firstNonEmpty(q.Get("fp"), "chrome")
		re["publicKey"] = q.Get("pbk")
		re["shortId"] = q.Get("sid")
		re["spiderX"] = q.Get("spx")
	}
}

func base64DecodeFlexible(s string) (string, error) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for len(clean)%4 != 0 {
		clean += "="
	}
	if b, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return string(b), nil
	}
	if b, err := base64.URLEncoding.DecodeString(clean); err == nil {
		return string(b), nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(clean, "=")); err == nil {
		return string(b), nil
	}
	return "", fmt.Errorf("base64 decode failed")
}

func getString(m map[string]any, key, def string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return def
}

func number(v any, def int) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		if n, err := strconv.Atoi(x); err == nil {
			return n
		}
	case int:
		return x
	}
	return def
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstQuery(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func defaultPort(raw string, def int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return def
	}
	return n
}

func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitHostPort(s string, def int) (string, int) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, def
	}
	return s[:idx], defaultPort(s[idx+1:], def)
}

func splitOnce(s, sep string) (string, string) {
	idx := strings.Index(s, sep)
	if idx < 0 {
		return "", s
	}
	return s[:idx], s[idx+len(sep):]
}

func decodeFragment(s string) string {
	if s == "" {
		return ""
	}
	if v, err := url.QueryUnescape(s); err == nil {
		return v
	}
	return s
}

func stableJSON(m map[string]any, omit string) string {
	cp := make(map[string]any, len(m))
	for k, v := range m {
		if k != omit {
			cp[k] = v
		}
	}
	b, _ := json.Marshal(cp)
	return string(b)
}
