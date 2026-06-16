# VPNproxi

VPNproxi is a standalone control panel for running an IPsec gateway with optional Xray-based selective egress.

It is built for one operator, one gateway host, and one simple job:

- accept IKEv2/IPsec client connections on a gateway VPS;
- keep stable traffic on direct NAT when needed;
- send selected client traffic through an external 3x-ui / Xray node when needed;
- expose the whole flow through one lightweight web UI.

VPNproxi ships as one Go binary with an embedded frontend. No Node runtime. No external database.

## What it does

- Manages an IPsec gateway based on StrongSwan.
- Accepts one external 3x-ui / Xray share link as the outbound route.
- Supports:
  - `vless://`
  - `vmess://`
  - `trojan://`
  - `ss://`
  - `hysteria2://` / `hy2://`
  - `wireguard://` / `wg://`
- Applies one of three routing modes:
  - `Direct NAT`
  - `Selective Xray`
  - `Force Xray`
- Generates and applies:
  - Xray config
  - StrongSwan config
  - firewall and transparent-routing rules
  - geodata update timer and update script
- Shows:
  - host status
  - IPsec sessions
  - per-client traffic counters
  - activity log

## Quick Links

- [Quick start](#quick-start)
- [Gateway requirements](#gateway-requirements)
- [External server requirements](#external-server-requirements)
- [Fast operator flow](#fast-operator-flow)
- [Routing modes](#routing-modes)
- [Documentation map](#documentation-map)
- [Development](#development)

## Quick Start

On a clean Debian or Ubuntu VPS:

```bash
sudo ./scripts/install.sh --domain vpn.example.com --port 8443 --email admin@example.com
```

Open:

```text
https://vpn.example.com/
```

Without a domain, the installer can run the UI on plain HTTP:

```bash
sudo ./scripts/install.sh --port 8443
```

The installer asks for an administrator username and password and writes the password hash to:

```text
/etc/vpnproxi/admin.json
```

The generated CA certificate for client trust is:

```text
/etc/swanctl/x509ca/vpnproxi-ca.crt
```

VPNproxi does not create a default IPsec user automatically. Add client credentials explicitly in the UI, then apply the draft.

## Gateway Requirements

Prepare one gateway host with:

- clean Debian or Ubuntu;
- public IP address;
- DNS `A` record such as `vpn.example.com` pointing to that host;
- `500/udp` and `4500/udp` open for IPsec;
- `80/tcp` and `443/tcp` open when the UI is published with `--domain`.

## External Server Requirements

VPNproxi manages the gateway. It does not deploy or manage the external exit server.

The external server must already provide one working 3x-ui / Xray-compatible share link.

Minimal external-node prerequisites:

- a reachable VPS outside the restricted network you want to bypass;
- a working 3x-ui or equivalent Xray-compatible node on that VPS;
- one exported share link from that node;
- one of the supported protocols:
  - `vless`
  - `vmess`
  - `trojan`
  - `ss`
  - `hysteria2` / `hy2`
  - `wireguard` / `wg`

## Fast Operator Flow

Typical production flow:

1. Deploy VPNproxi on the gateway VPS.
2. Sign in to the UI.
3. Set `VPN domain`, for example `vpn.example.com`.
4. Add one or more IPsec clients in the `IPsec clients` section.
5. Paste the external share link from the external 3x-ui / Xray node.
6. Run `Check route`.
7. Choose a routing mode.
8. Click `Apply`.
9. Configure the end-user device as an IKEv2 client:
   - server: `vpn.example.com`
   - remote ID: `vpn.example.com`
   - username/password: from the `IPsec clients` section.
10. Import the generated CA certificate if the client device does not already trust the selected IPsec certificate chain.

If the external share link changes later:

1. replace only that link in the UI;
2. run `Check route` again;
3. apply the updated draft again.

## Routing Modes

### Direct NAT

The stable production-safe default.

- IPsec client traffic is forwarded and masqueraded through the gateway.
- Xray is not in the active datapath.
- Proxy rules stay saved in the draft but do not affect traffic.

### Selective Xray

Only matched traffic goes through the external outbound.

Proxy matches can come from:

- `Always proxy domains`
- `Always proxy IP/CIDR`
- `Always proxy ports`
- Runet blocked-list rules

Direct rules override proxy rules.

### Force Xray

All client traffic goes through the external outbound except explicit direct overrides. Local DNS stays direct to keep resolution stable.

## Runet Blocked Lists

When the blocked-list toggle is enabled, VPNproxi adds:

- `geosite:ru-blocked-all`
- `geoip:ru-blocked`
- `geoip:ru-blocked-community`
- `geoip:telegram`

The lists are refreshed by `vpnproxi-geodata.timer`. The UI host status shows the last loaded update time for `geoip.dat` and `geosite.dat`.

## Documentation Map

- [SECURITY.md](SECURITY.md) - security defaults and handling guidance
- [docs/OPERATIONS.md](docs/OPERATIONS.md) - runtime operations, health checks, logs, recovery
- [docs/RELEASE.md](docs/RELEASE.md) - pre-release checklist before publishing to GitHub or shipping to production

## Project Layout

- [cmd/vpnproxi/main.go](cmd/vpnproxi/main.go) - binary entrypoint
- [cmd/vpnproxi/static](cmd/vpnproxi/static) - embedded frontend and built-in docs
- [internal/app](internal/app) - HTTP API, auth, state, activity log
- [internal/link/parser.go](internal/link/parser.go) - share-link parsing and probing
- [internal/render/render.go](internal/render/render.go) - generated Xray and StrongSwan configs
- [internal/system/apply.go](internal/system/apply.go) - Linux apply and status layer
- [scripts/install.sh](scripts/install.sh) - VPS installation script

## Local Run on macOS

macOS can run the UI and parser locally, but cannot apply Linux networking, firewall, or IPsec host configuration.

```bash
go run ./cmd/vpnproxi --addr 127.0.0.1:18080 --state ./dev-state.json --apply-enabled=false --log ./vpnproxi.log
```

Open:

```text
http://127.0.0.1:18080/
```

## Development

```bash
go test ./...
go vet ./...
go build -o /tmp/vpnproxi ./cmd/vpnproxi
```

## Current Limits

- Real `Apply` is Linux-only.
- The first production validation should be done on a disposable VPS before using a live server.
- The project is intentionally single-operator and single-instance, not multi-tenant.
