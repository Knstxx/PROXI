# VPNproxi Operations

## Deployment Prerequisites

Gateway host:

- clean Debian or Ubuntu VPS;
- public IP address;
- DNS `A` record pointing the VPN domain to that host;
- `500/udp` and `4500/udp` open for IPsec;
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
- `xray` - transparent receiver for the IPsec subnet and outbound proxy engine.
- `vpnproxi-geodata.timer` - daily runetfreedom geosite/geoip update.

## Important Paths

- `/etc/vpnproxi/state.json` - source of truth for UI state.
- `/var/log/vpnproxi/vpnproxi.log` - VPNproxi activity log, rotated by size in-app and by `logrotate`.
- `/var/log/xray/access.log` and `/var/log/xray/error.log` - Xray logs, rotated by `/etc/logrotate.d/vpnproxi-xray`.
- `/usr/local/etc/xray/config.json` - generated Xray config.
- `/etc/swanctl/swanctl.conf` - generated StrongSwan config.
- `/usr/local/bin/vpnproxi-updown.sh` - StrongSwan updown callback.
- `/usr/local/bin/vpnproxi-firewall.sh` - generated firewall/sysctl reconciler.
- `/usr/local/etc/vpnproxi/users_traffic_route.csv` - generated login to local Xray transparent inbound port map.

## Traffic Counters

- Per-client `In/Out` counters in the UI come from live Xray statistics. They are runtime memory counters and reset when:
  - the operator presses `Reset traffic` in the UI;
  - Xray restarts;
  - the host reboots.
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
