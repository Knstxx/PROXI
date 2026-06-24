# VPNproxi operator guide

## Deployment flow

1. VPNproxi is installed on a clean Debian or Ubuntu VPS.
2. The installer asks for an administrator username and password; the UI is opened with those credentials.
3. The current host is shown in the Endpoint panel.
4. The DNS `A` record should point the VPN domain to the public IP of this server.
5. That domain is entered into `VPN domain`; then the external 3x-ui/Xray share link is added.
6. If the external route changed, run `Check route`, then apply the configuration on the Linux VPS.

## Minimal quick start

1. Prepare one gateway VPS with a public IP.
2. Point a DNS `A` record such as `vpn.example.com` to that gateway.
3. Open `500/udp` and `4500/udp` for IPsec.
4. Open `80/tcp` and `443/tcp` when the UI is exposed through `--domain`.
5. Run the installer on the gateway:

```bash
sudo ./scripts/install.sh --domain vpn.example.com --port 8443 --email admin@example.com
```

6. Sign in to the UI.
7. Set `VPN domain` to `vpn.example.com`.
8. Add IPsec client credentials in `IPsec clients`.
9. Paste the external share link, run `Check route`, choose a routing mode, then apply.
10. Configure client devices with:
   - server: `vpn.example.com`
   - remote ID: `vpn.example.com`
   - username/password: from the `IPsec clients` section.

## External server prerequisites

VPNproxi manages the gateway, not the external exit node.

The external server must already have a working 3x-ui/Xray-compatible outbound node and one exported share link. Operationally the simplest pattern is:

1. Install and configure 3x-ui on the external VPS.
2. Create one client entry there.
3. Copy the generated share link.
4. Paste that link into VPNproxi.
5. Run `Check route`.
6. Apply the draft on the gateway.

Supported link formats are `vless`, `vmess`, `trojan`, `ss`, `hysteria2`, `hy2`, `wireguard`, and `wg`.

## DNS and IPsec host

`IPsec server address` is what clients should use as the VPN server hostname.

If `VPN domain` is empty, VPNproxi shows the current browser host. On a real VPS opened by IP address, this is usually the public server IP. For production, use a DNS name instead of a raw IP whenever possible.

Recommended production setup:

- DNS record: `vpn.example.com A <server-public-ip>`.
- `VPN domain` value: `vpn.example.com`.
- The installer is run with `--domain vpn.example.com` when UI HTTPS through Caddy is required.
- Keep UDP `500` and `4500` open for IPsec.
- Keep the UI port open only to trusted admin networks when possible.

## Certificates

VPNproxi uses two certificate paths:

- UI HTTPS is handled by Caddy when the installer runs with `--domain`.
- IPsec identity is handled by StrongSwan using `IPsec certificate` and `IPsec private key`.

The installer generates a local CA and an IPsec server certificate with the provided domain as SAN. Clients must trust `/etc/swanctl/x509ca/vpnproxi-ca.crt` or use a certificate chain that your client devices already trust. If `IPsec certificate` points to a fullchain bundle, Apply splits it into a leaf certificate for StrongSwan and intermediate certificates under `/etc/swanctl/x509ca`.

## UI access

The admin username and bcrypt password hash are stored in `/etc/vpnproxi/admin.json`. The session cookie is signed with the secret from the same file and is issued as `HttpOnly`.

## External route

The external route field accepts one 3x-ui/Xray share link. When the link changes, run `Check route`, then apply the draft to the host. Supported protocols are `vless`, `vmess`, `trojan`, `ss`, `hysteria2`, `hy2`, `wireguard`, and `wg`.

The link becomes the external Xray outbound. It is used only in `Selective Xray` and `Force Xray` modes.

## Routing

Routing mode defines what happens to IPsec client traffic:

- `Direct NAT` is the stable production mode. Traffic goes out through gateway NAT and Xray is not in the datapath.
- `Selective Xray` sends only proxy-rule matches through the external outbound.
- `Force Xray` sends all client traffic through the external outbound except explicit direct overrides. Local DNS stays direct so domain resolution remains stable.

In `Selective Xray`, traffic goes through the external outbound when it matches proxy rules:

- Always proxy domains
- Always proxy IP/CIDR
- Always proxy ports
- Runet blocked list rules

Direct rules override proxy rules. Use them for banks, private resources, internal networks, and anything that must stay local.

## Runet blocked list source

When `Runet blocked lists` is enabled, VPNproxi adds Xray routing rules for `geosite:ru-blocked-all`, `geoip:ru-blocked`, `geoip:ru-blocked-community`, and `geoip:telegram`.

This toggle uses runetfreedom blocked datasets and is refreshed by a systemd timer. The `Host status` panel shows the last successful update time of the loaded lists.

Data files are updated by the generated systemd timer `vpnproxi-geodata.timer`. The timer runs `/usr/local/bin/vpnproxi-geodata-update.sh`, which downloads the latest release:

- `geoip.dat` from `https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat`
- `geosite.dat` from `https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat`

The files are installed into `/usr/local/share/xray` and used by Xray as standard `geoip.dat` and `geosite.dat`.

## Apply behavior

Apply writes generated Xray and StrongSwan files, runs the firewall/sysctl reconciler, validates Xray config, restarts Xray, reloads StrongSwan credentials, and restarts StrongSwan.

On macOS the app runs in local-only mode. Real Apply is Linux-only.

## Settings shown in UI

The UI intentionally exposes only operator-level settings:

- external outbound link
- VPN domain and subnet
- routing mode
- Xray transparent port; legacy mark and table are kept for compatibility
- IPsec certificate and key paths
- routing rules
- IPsec users

Advanced file paths, geodata paths, DNS servers, and generated script paths stay on secure defaults to keep the control panel simple.
