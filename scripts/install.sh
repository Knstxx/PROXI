#!/usr/bin/env bash
set -euo pipefail

PORT="8443"
DOMAIN=""
EMAIL=""
VERSION_BIN="/usr/local/bin/vpnproxi"
ENV_FILE="/etc/vpnproxi/vpnproxi.env"
AUTH_FILE="/etc/vpnproxi/admin.json"
TRAFFIC_FILE="/var/lib/vpnproxi/traffic.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$(id -u)" != "0" ]]; then
  echo "run as root" >&2
  exit 1
fi

apt-get update
apt-get install -y curl ca-certificates openssl iproute2 iptables ipset dnsmasq-base logrotate git golang-go ufw fail2ban unattended-upgrades \
  strongswan-pki strongswan-swanctl charon-systemd \
  libstrongswan-standard-plugins libstrongswan-extra-plugins libcharon-extra-plugins

cat > /etc/sysctl.d/99-vpnproxi.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null

if ! command -v xray >/dev/null 2>&1; then
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

install -d -m 0750 /etc/vpnproxi
install -d -m 0750 /var/lib/vpnproxi
install -d -m 0755 /usr/local/etc/vpnproxi
install -d -m 0700 /etc/swanctl/private
install -d -m 0755 /etc/swanctl/x509 /etc/swanctl/x509ca

CERT_NAME="${DOMAIN:-vpnproxi.local}"
if [[ ! -f /etc/swanctl/private/vpnproxi.key || ! -f /etc/swanctl/x509/vpnproxi-leaf.crt || ! -f /etc/swanctl/x509ca/vpnproxi-ca.crt ]]; then
  WORKDIR="$(mktemp -d)"
  trap 'rm -rf "$WORKDIR"' EXIT
  pki --gen --type rsa --size 4096 --outform pem > "$WORKDIR/ca.key.pem"
  pki --self --ca --lifetime 3650 --in "$WORKDIR/ca.key.pem" --type rsa \
    --dn "CN=VPNproxi Root CA" --outform pem > "$WORKDIR/ca.cert.pem"
  pki --gen --type rsa --size 4096 --outform pem > "$WORKDIR/server.key.pem"
  pki --pub --in "$WORKDIR/server.key.pem" --type rsa \
    | pki --issue --lifetime 1825 \
      --cacert "$WORKDIR/ca.cert.pem" --cakey "$WORKDIR/ca.key.pem" \
      --dn "CN=$CERT_NAME" --san "$CERT_NAME" \
      --flag serverAuth --flag ikeIntermediate --outform pem \
      > "$WORKDIR/server.cert.pem"
  install -m 0600 "$WORKDIR/server.key.pem" /etc/swanctl/private/vpnproxi.key
  install -m 0644 "$WORKDIR/server.cert.pem" /etc/swanctl/x509/vpnproxi-leaf.crt
  install -m 0644 "$WORKDIR/server.cert.pem" /etc/swanctl/x509/vpnproxi-full.crt
  install -m 0644 "$WORKDIR/ca.cert.pem" /etc/swanctl/x509ca/vpnproxi-ca.crt
fi

if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" <<EOF
VPNPROXI_STATE=/etc/vpnproxi/state.json
VPNPROXI_LOG=/var/log/vpnproxi/vpnproxi.log
VPNPROXI_TRAFFIC=$TRAFFIC_FILE
VPNPROXI_AUTH=$AUTH_FILE
EOF
  chmod 0600 "$ENV_FILE"
fi
if ! grep -q '^VPNPROXI_LOG=' "$ENV_FILE"; then
  echo 'VPNPROXI_LOG=/var/log/vpnproxi/vpnproxi.log' >> "$ENV_FILE"
fi
if ! grep -q '^VPNPROXI_AUTH=' "$ENV_FILE"; then
  echo "VPNPROXI_AUTH=$AUTH_FILE" >> "$ENV_FILE"
fi
if ! grep -q '^VPNPROXI_TRAFFIC=' "$ENV_FILE"; then
  echo "VPNPROXI_TRAFFIC=$TRAFFIC_FILE" >> "$ENV_FILE"
fi

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

install -d -m 0750 /var/log/vpnproxi
cat > /etc/logrotate.d/vpnproxi <<'EOF'
/var/log/vpnproxi/*.log {
  daily
  rotate 7
  maxsize 10M
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
  create 0640 root root
}
EOF

cat > /etc/logrotate.d/vpnproxi-xray <<'EOF'
/var/log/xray/*.log {
  daily
  rotate 7
  maxsize 20M
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
  create 0640 root root
}
EOF

if [[ ! -x ./vpnproxi ]]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "Go is required when ./vpnproxi binary is not present. Install Go or copy a built binary next to scripts/install.sh." >&2
    exit 1
  fi
  go build -o /tmp/vpnproxi ./cmd/vpnproxi
  install -m 0755 /tmp/vpnproxi "$VERSION_BIN"
else
  install -m 0755 ./vpnproxi "$VERSION_BIN"
fi

if [[ ! -f "$AUTH_FILE" ]]; then
  ADMIN_USERNAME="${VPNPROXI_ADMIN_USERNAME:-}"
  ADMIN_PASSWORD="${VPNPROXI_ADMIN_PASSWORD:-}"
  GENERATED_PASSWORD=""
  if [[ -z "$ADMIN_USERNAME" ]]; then
    if [[ -t 0 ]]; then
      read -r -p "Admin username [admin]: " ADMIN_USERNAME
      ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
    else
      ADMIN_USERNAME="admin"
    fi
  fi
  if [[ -z "$ADMIN_PASSWORD" ]]; then
    if [[ -t 0 ]]; then
      read -r -s -p "Admin password: " ADMIN_PASSWORD
      echo
      read -r -s -p "Repeat admin password: " ADMIN_PASSWORD_REPEAT
      echo
      if [[ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_REPEAT" ]]; then
        echo "admin passwords do not match" >&2
        exit 1
      fi
      if [[ -z "$ADMIN_PASSWORD" ]]; then
        echo "admin password cannot be empty" >&2
        exit 1
      fi
    else
      ADMIN_PASSWORD="$(openssl rand -base64 24)"
      GENERATED_PASSWORD="$ADMIN_PASSWORD"
    fi
  fi
  VPNPROXI_ADMIN_PASSWORD="$ADMIN_PASSWORD" "$VERSION_BIN" --create-admin --auth "$AUTH_FILE" --admin-username "$ADMIN_USERNAME"
  chmod 0600 "$AUTH_FILE"
fi

LISTEN_ADDR=":$PORT"
PUBLIC_URL="http://0.0.0.0:$PORT/"

if [[ -n "$DOMAIN" ]]; then
  LISTEN_ADDR="127.0.0.1:$PORT"
  if apt-get install -y caddy; then
    if [[ -n "$EMAIL" ]]; then
      CADDY_GLOBAL=$'{\n  email '"$EMAIL"$'\n}\n'
    else
      CADDY_GLOBAL=""
    fi
    cat > /etc/caddy/Caddyfile <<EOF
$CADDY_GLOBAL
$DOMAIN {
  reverse_proxy 127.0.0.1:$PORT
}
EOF
    systemctl enable --now caddy
    systemctl reload caddy || systemctl restart caddy
    PUBLIC_URL="https://$DOMAIN/"
  else
    echo "WARNING: caddy install failed; UI will be plain HTTP on :$PORT" >&2
    LISTEN_ADDR=":$PORT"
  fi
fi

ufw allow OpenSSH
ufw allow 500/udp
ufw allow 4500/udp
if [[ -n "$DOMAIN" ]]; then
  ufw allow 80/tcp
  ufw allow 443/tcp
else
  ufw allow "$PORT/tcp"
fi
ufw --force enable
systemctl enable --now fail2ban

cat > /etc/systemd/system/vpnproxi.service <<EOF
[Unit]
Description=VPNproxi control panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$VERSION_BIN --addr $LISTEN_ADDR
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/vpnproxi-apply.service <<'EOF'
[Unit]
Description=VPNproxi host apply
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/vpnproxi/vpnproxi.env
ExecStart=/usr/local/bin/vpnproxi --apply-once

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vpnproxi-apply.service
systemctl restart vpnproxi 2>/dev/null || systemctl enable --now vpnproxi
systemctl start vpnproxi-apply.service

echo "VPNproxi is running on $PUBLIC_URL"
echo "Admin credentials are stored in $AUTH_FILE"
if [[ -n "${GENERATED_PASSWORD:-}" ]]; then
  echo "Generated admin username: $ADMIN_USERNAME"
  echo "Generated admin password: $GENERATED_PASSWORD"
fi
echo "IPsec CA certificate for clients: /etc/swanctl/x509ca/vpnproxi-ca.crt"
