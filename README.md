# PROXI

VPNproxi is a lightweight standalone control panel for a single intermediate VPS that turns IPsec client traffic into a managed gateway. The stable production mode is Direct NAT; Xray egress can be enabled explicitly for selective or full proxy routing.

The intended flow is:

1. A user connects to the VPS with IKEv2/IPsec.
2. StrongSwan runs the generated `vpnproxi-updown.sh` callback.
3. VPNproxi applies managed firewall rules for the selected routing mode.
4. Direct NAT sends VPN client traffic out through the gateway. Selective and force-proxy modes send VPN-client TCP and UDP traffic through Xray using managed Linux transparent-proxy rules, while local DNS stays direct.

The app is one Go binary with embedded UI. There is no Node runtime and no external database.

## Features

- Dark digital UI for one-operator administration.
- Field-level help tooltips in the UI.
- Share-link parser for:
  - `vless://`
  - `vmess://`
  - `trojan://`
  - `ss://`
  - `hysteria2://` / `hy2://`
  - `wireguard://` / `wg://`
- Routing modes:
  - Direct NAT for stable production gateway traffic;
  - Selective Xray for proxy rules only;
  - Force Xray for sending all IPsec client traffic through the external outbound.
- Generated Xray config with:
  - local transparent Xray inbound for the IPsec subnet;
  - external outbound;
  - direct fallback;
  - force-proxy and force-direct rules;
  - runetfreedom geosite/geoip routing;
  - `sockopt.mark` on outbounds to avoid transparent-proxy routing loops.
- Generated StrongSwan `swanctl.conf`.
- Generated StrongSwan updown callback and managed firewall script.
- Daily geodata update systemd timer.
- Activity log with in-app rotation and `logrotate` configuration.
- Xray log rotation for generated access/error logs.

## Quick Start

On a clean Debian/Ubuntu VPS:

```bash
sudo ./scripts/install.sh --domain vpn.example.com --port 8443 --email admin@example.com
```

Open:

```text
https://vpn.example.com/
```

Without a domain, the installer runs plain HTTP on the selected port:

```bash
sudo ./scripts/install.sh --port 8443
```

The installer asks for an administrator username and password. The bcrypt password hash and session secret are stored in:

```text
/etc/vpnproxi/admin.json
```

The initial state does not create any IPsec users automatically. Add client credentials explicitly in the UI, then apply the draft.

The generated IPsec CA certificate for client trust is:

```text
/etc/swanctl/x509ca/vpnproxi-ca.crt
```

## Local Run on macOS

macOS can run the UI and parser, but cannot apply IPsec/firewall host networking.

```bash
go run ./cmd/vpnproxi --addr 127.0.0.1:18080 --state ./dev-state.json --apply-enabled=false --log ./vpnproxi.log
```

Open:

```text
http://127.0.0.1:18080/
```

## Routing Model

Direct NAT is the default and production-safe mode. In this mode IPsec client traffic is forwarded and masqueraded through the gateway, and Xray is not in the datapath.

Selective Xray mode proxies traffic only when it matches:

- `Always proxy domains`
- `Always proxy IP/CIDR`
- `Always proxy ports`
- `geosite:ru-blocked-all`
- `geoip:ru-blocked`
- `geoip:ru-blocked-community`
- `geoip:telegram`

The Runet toggle uses runetfreedom blocked datasets and refreshes them with a systemd timer. The UI host status shows the last loaded update time for `geoip.dat` and `geosite.dat`.

Direct override rules have higher priority than proxy rules. Force Xray mode sends all IPsec client traffic through the external outbound after direct overrides.

## Project Layout

- [cmd/vpnproxi/main.go](cmd/vpnproxi/main.go) - binary entrypoint and embedded UI.
- [cmd/vpnproxi/static](cmd/vpnproxi/static) - embedded frontend assets.
- [internal/link/parser.go](internal/link/parser.go) - share-link parser.
- [internal/render/render.go](internal/render/render.go) - Xray/StrongSwan renderers.
- [internal/system/apply.go](internal/system/apply.go) - Linux apply/status layer.
- [internal/app](internal/app) - HTTP API, state store, validation, activity log.
- [docs/OPERATIONS.md](docs/OPERATIONS.md) - production operations and recovery.
- [docs/RELEASE.md](docs/RELEASE.md) - pre-publish checklist for GitHub and production releases.
- [SECURITY.md](SECURITY.md) - security guidance.

## Development

```bash
go test ./...
go build -o /tmp/vpnproxi ./cmd/vpnproxi
```

## Current Limitations

- Real `Apply to host` is Linux-only.
- The first production validation should be done on a disposable VPS before using a live server.
- The app is designed for one operator and one instance, not multi-tenant hosting.
