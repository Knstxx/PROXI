# VPNproxi Operations

## Deployment Prerequisites

Gateway host:

- clean Debian or Ubuntu VPS;
- public IP address;
- DNS `A` record pointing the VPN domain to that host;
- `500/udp`, `4500/udp`, and IP protocol `50` (`ESP`) open for IPsec;
- `80/tcp` and `443/tcp` open when the UI is published through `--domain`.

External exit host:

- separate VPS reachable from the gateway;
- running 3x-ui or equivalent Xray-compatible node;
- at least one exported share link supported by VPNproxi:
  - `vless`
  - `vmess`
  - `trojan`
  - `ss`
  - `hysteria2` / `hy2`
  - `wireguard` / `wg`

## Services

- `vpnproxi.service` - web UI and API.
- `vpnproxi-apply.service` - reapplies firewall, Xray, and StrongSwan state on boot.
- `strongswan` - IKEv2/IPsec endpoint.
- `xray` - transparent TCP/UDP classifier and direct/external outbound engine for Selective and Force modes.
- `vpnproxi-dnsmasq` - project-scoped DNS cache for IPsec clients; it does not decide traffic routes. It terminates private reverse and `.local` queries locally and uses Xray's parallel DNS-over-HTTPS as the normal upstream. Direct Cloudflare and Google templates are kept for outages, but only one verified resolver is active at a time.
- `vpnproxi-dns-health.timer` - probes the client resolver path and the primary Xray DNS bridge separately every five seconds. It atomically switches dnsmasq's `servers-file` to direct fallback after two primary failures and restores the encrypted primary after six good checks plus a two-minute minimum fallback dwell. The transition uses `SIGHUP`; only repeated client-path failures restart dnsmasq, with a two-minute cooldown. It never restarts the shared Xray datapath.
- `vpnproxi-geodata.timer` - automatic runetfreedom `geoip.dat` and `geosite.dat` refresh for Xray routing categories.

## Important Paths

- `/etc/vpnproxi/state.json` - source of truth for UI state.
- `/var/lib/vpnproxi/traffic.json` - persistent per-client traffic totals. It is atomically rewritten, not appended.
- `/var/log/vpnproxi/vpnproxi.log` - VPNproxi activity log, rotated by size in-app and by `logrotate`.
- `/var/log/xray/access.log` and `/var/log/xray/error.log` - Xray logs, rotated by `/etc/logrotate.d/vpnproxi-xray`.
- `/usr/local/etc/xray/config.json` - generated Xray config.
- `/usr/local/bin/xray` - gateway core; clean installs pin `v26.7.28` unless `VPNPROXI_XRAY_VERSION` explicitly overrides it.
- `/etc/swanctl/swanctl.conf` - generated StrongSwan config.
- `/usr/local/bin/vpnproxi-updown.sh` - StrongSwan updown callback.
- `/usr/local/bin/vpnproxi-firewall.sh` - generated firewall/sysctl reconciler.
- `/usr/local/etc/vpnproxi/users_traffic_route.csv` - generated login to local Xray transparent inbound port map.

## Traffic Counters

- Per-client `In` counters come from the Xray direct outbound in Selective/Force modes and kernel FORWARD counters for traffic that bypasses Xray.
- Per-client `Out` counters come from Xray outbound counters for traffic sent to the external proxy.
- VPNproxi samples both sources and persists cumulative deltas in `/var/lib/vpnproxi/traffic.json`.
- The counters survive Xray restarts, config applies, and host reboots. They reset only when the operator presses `Reset traffic` in the UI.
- Host-level totals in `Host status` come from `/proc/net/dev`. These are kernel interface counters, not VPNproxi database values. They remain cumulative until reboot or interface reset.

## Health Checks

```bash
systemctl status vpnproxi vpnproxi-apply.service xray strongswan vpnproxi-geodata.timer
swanctl --list-conns
swanctl --list-sas
iptables -t mangle -S VPNPROXI_TPROXY
iptables -t nat -S VPNPROXI_REDIRECT
iptables -S INPUT | grep 0x2333
iptables -t nat -S POSTROUTING | grep 10.10.10.0/24
xray run -test -config /usr/local/etc/xray/config.json
```

## Logs

```bash
journalctl -u vpnproxi -n 100 --no-pager
tail -n 200 /var/log/vpnproxi/vpnproxi.log
journalctl -u xray -n 100 --no-pager
journalctl -u strongswan -n 100 --no-pager
```

The UI shows the last activity-log lines in the right sidebar.

## Recovery

1. Open the UI and check the visible settings.
2. For stable access, set Routing mode to `Direct NAT`, review the draft, then apply. Use `Selective Xray` or `Force Xray` only when validating the Xray datapath.
3. If Xray config is broken, fix the share link or routing values, run `Check route` when the external link changed, then apply again.
4. If the UI is unavailable, inspect `/etc/vpnproxi/state.json`, then restart:

```bash
systemctl restart vpnproxi
```

5. If IPsec clients connect but traffic does not route:

```bash
systemctl start vpnproxi-apply.service
```
