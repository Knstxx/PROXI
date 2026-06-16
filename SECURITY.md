# Security Policy

VPNproxi controls host networking, StrongSwan and Xray. Treat the web UI as a privileged admin surface.

## Required Production Defaults

- Use a strong administrator password. The installer stores only a bcrypt hash in `/etc/vpnproxi/admin.json`.
- Create IPsec client credentials explicitly in the UI. The initial state does not ship with a default VPN user.
- Put the UI behind HTTPS. `scripts/install.sh --domain example.com` installs Caddy and reverse-proxies to localhost.
- Restrict access to the UI with firewall rules or a private admin network when possible.
- Do not paste share links into public logs or issue trackers. Share links contain credentials.
- Keep `/etc/vpnproxi/admin.json`, `/etc/vpnproxi/vpnproxi.env`, `/etc/vpnproxi/state.json`, and `/etc/swanctl/private/*` readable only by root.
- Browser responses set `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy` by default. Keep reverse proxies from stripping them.
- Review generated config preview before `Apply to host` on production.

## Reporting Issues

This is currently a private/operator-focused project. Do not include real VPN links, tokens, private keys, server IPs, or user credentials in bug reports.
