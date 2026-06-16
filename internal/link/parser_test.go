package link

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestParseVLESSReality(t *testing.T) {
	out, err := Parse("vless://11111111-2222-4333-8444-555555555555@example.com:443?type=tcp&security=reality&pbk=pub&sid=abcd&fp=chrome&sni=www.example.com&flow=xtls-rprx-vision#node")
	if err != nil {
		t.Fatal(err)
	}
	if out.Protocol != "vless" {
		t.Fatalf("protocol=%s", out.Protocol)
	}
	stream := out.StreamSettings
	if stream["security"] != "reality" {
		t.Fatalf("security=%v", stream["security"])
	}
	settings := out.Settings["vnext"].([]any)[0].(map[string]any)
	if settings["address"] != "example.com" {
		t.Fatalf("address=%v", settings["address"])
	}
}

func TestParseHysteria2(t *testing.T) {
	out, err := Parse("hysteria2://secret@example.com:8443?sni=front.example&alpn=h3#hy")
	if err != nil {
		t.Fatal(err)
	}
	if out.Protocol != "hysteria" {
		t.Fatalf("protocol=%s", out.Protocol)
	}
	if out.StreamSettings["network"] != "hysteria" {
		t.Fatalf("network=%v", out.StreamSettings["network"])
	}
}

func TestParseVMess(t *testing.T) {
	body := map[string]any{"ps": "node", "add": "1.2.3.4", "port": "443", "id": "uuid", "net": "ws", "tls": "tls", "host": "ex.com", "path": "/ws"}
	raw, _ := json.Marshal(body)
	out, err := Parse("vmess://" + base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if out.Protocol != "vmess" {
		t.Fatalf("protocol=%s", out.Protocol)
	}
	if out.StreamSettings["network"] != "ws" {
		t.Fatalf("network=%v", out.StreamSettings["network"])
	}
}

func TestProbeTargetTCPProtocols(t *testing.T) {
	out, err := Parse("vless://11111111-2222-4333-8444-555555555555@example.com:8443?type=tcp&security=tls#node")
	if err != nil {
		t.Fatal(err)
	}
	network, host, port, err := ProbeTarget(out)
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp" || host != "example.com" || port != 8443 {
		t.Fatalf("got %s %s %d", network, host, port)
	}
}

func TestProbeTargetWireGuard(t *testing.T) {
	out, err := Parse("wireguard://secret@example.com:51820?publickey=peerkey&address=10.0.0.2/32#wg")
	if err != nil {
		t.Fatal(err)
	}
	network, host, port, err := ProbeTarget(out)
	if err != nil {
		t.Fatal(err)
	}
	if network != "udp" || host != "example.com" || port != 51820 {
		t.Fatalf("got %s %s %d", network, host, port)
	}
}
