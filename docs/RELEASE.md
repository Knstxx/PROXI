# VPNproxi Release Checklist

Use this checklist before pushing the repository to GitHub or tagging a production release.

## Secrets and Environment

- Confirm the repository contains no real:
  - share links;
  - IPsec usernames/passwords;
  - admin passwords;
  - private keys;
  - server IPs or internal LAN addresses.
- Keep only example domains such as `vpn.example.com` in docs and screenshots.
- Do not commit local `dev-state.json`, generated logs, test binaries, or temporary exports.

## Verification

Run:

```bash
go test ./...
go vet ./...
go build -o /tmp/vpnproxi ./cmd/vpnproxi
```

## Production Packaging

- Verify `scripts/install.sh` still:
  - prompts for admin credentials;
  - writes `/etc/vpnproxi/admin.json` with `0600`;
  - exposes only `80/443` when a domain is used, or only the selected UI port otherwise;
  - leaves IPsec on `500/udp` and `4500/udp`.
- Verify the service starts with:

```bash
systemctl status vpnproxi xray strongswan vpnproxi-geodata.timer
```

## UI Review

- Login screen renders first, without exposing the main dashboard before authentication.
- Draft/apply/discard flow is visible and works.
- `Check route` is required only when the external share link changes.
- `Reset traffic` clears client Xray counters without pretending to reset host network totals.
- Documentation and activity log start collapsed.
