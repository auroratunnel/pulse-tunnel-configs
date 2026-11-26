#!/usr/bin/env bash
# =============================================================================
# pulse-install.sh — idempotent full-stack installer for Pulse Tunnel
#
# Reproduces the reference VPS (152.42.232.252) exactly:
#   22   OpenSSH                 222,777  stunnel4 -> sshd
#   80   nginx WS none-TLS       81       nginx status page
#   443  nginx stream SNI router 7100-7900 badvpn-udpgw (9)
#   8443 OpenVPN tcp            1194/udp  OpenVPN
#   10001-10021 Xray inbounds   10080     websockify (SSH over WS)
#   VLESS/VMess/Trojan/SS  WS+gRPC over 80/443
#
# SAFE TO RE-RUN: every step is idempotent. Re-running on an already-configured
# box leaves it working (this is how it is validated against the reference VPS).
#
# Usage:
#   pulse-install.sh --ip <public-ip> [--pki-b64 <base64-tar>] [--skip-verify]
#
# --pki-b64  tar.gz (base64) holding ca.crt/server.crt/server.key. Supplying it
#            makes the new VPS serve OpenVPN with the SAME CA already embedded
#            in the shipped client profiles — without it, existing profiles
#            would fail server verification.
# =============================================================================
set -euo pipefail

IP=""
PKI_B64=""
SKIP_VERIFY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ip)          IP="${2:-}"; shift 2 ;;
    --pki-b64)     PKI_B64="${2:-}"; shift 2 ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;36m[pulse]\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32mOK\033[0m   %s\n' "$*"; }
warn() { printf '  \033[1;33mWARN\033[0m %s\n' "$*"; }
die()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# --- preflight -------------------------------------------------------------
[ "$(id -u)" = "0" ] || die "must run as root"
[ -n "$IP" ] || die "--ip <public-ip> is required (used for the TLS SAN)"

ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
[ "$ARCH" = "amd64" ] || die "this installer targets amd64 VPS images (got $ARCH)"

if [ ! -f /etc/os-release ]; then die "not a Debian/Ubuntu system"; fi
# shellcheck disable=SC1091
. /etc/os-release
log "target $IP on ${PRETTY_NAME:-unknown} ($ARCH)"

export DEBIAN_FRONTEND=noninteractive

# --- 1. packages -----------------------------------------------------------
log "1/11 packages"
APT_PKGS=(
  nginx libnginx-mod-stream
  openvpn easy-rsa
  stunnel4
  openssh-server
  websockify socat
  curl wget unzip zip ca-certificates openssl
  iptables
  build-essential cmake pkg-config git
  libnspr4-dev libnss3-dev
)
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq "${APT_PKGS[@]}" >/dev/null 2>&1 || {
  apt-get install -y -qq "${APT_PKGS[@]}" || die "apt-get install failed"
}
ok "packages installed"

# --- 2. xray ---------------------------------------------------------------
log "2/11 xray"
XRAY_VER="26.11.9"
XRAY_CUR="$(/usr/local/bin/xray version 2>/dev/null || true)"
if ! grep -q "Xray $XRAY_VER" <<<"$XRAY_CUR"; then
  tmp=$(mktemp -d)
  ( cd "$tmp" \
    && curl -fsSL -o x.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VER}/Xray-linux-64.zip" \
    && unzip -o -q x.zip \
    && install -m 755 xray /usr/local/bin/xray )
  rm -rf "$tmp"
fi
# NB: `| head` closes the pipe early and SIGPIPEs the writer; with pipefail
# that would abort the whole script (exit 141). Always guard these.
/usr/local/bin/xray version 2>/dev/null | head -1 | sed 's/^/    /' || true
id xray >/dev/null 2>&1 || useradd --system --home /var/lib/xray --shell /usr/sbin/nologin xray
mkdir -p /usr/local/etc/xray /var/lib/xray
chown -R xray:xray /var/lib/xray 2>/dev/null || true
ok "xray ready"

# --- 3. xray config --------------------------------------------------------
log "3/11 xray config (9 inbounds)"
UUID="53bf28a5-a3f1-4f03-8d87-70b1b40e291a"
TROJAN_PASS="15ec32096d7834d6bcadc48e8073a974"
SS_PASS="73c76bbb056eeb85de5d7c21f1df8f4b"
SS_METHOD="aes-256-gcm"

cat > /usr/local/etc/xray/config.json <<XRAYEOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "vless-ws",   "listen": "127.0.0.1", "port": 10001, "protocol": "vless",
      "settings": { "clients": [ { "id": "$UUID" } ], "decryption": "none" },
      "streamSettings": { "network": "ws", "security": "none" } },
    { "tag": "vless-xhttp","listen": "127.0.0.1", "port": 10021, "protocol": "vless",
      "settings": { "clients": [ { "id": "$UUID" } ], "decryption": "none" },
      "streamSettings": { "network": "xhttp", "security": "none" } },
    { "tag": "vless-grpc", "listen": "127.0.0.1", "port": 10011, "protocol": "vless",
      "settings": { "clients": [ { "id": "$UUID" } ], "decryption": "none" },
      "streamSettings": { "network": "grpc", "security": "none", "grpcSettings": { "serviceName": "vless" } } },
    { "tag": "vmess-ws",   "listen": "127.0.0.1", "port": 10002, "protocol": "vmess",
      "settings": { "clients": [ { "id": "$UUID", "alterId": 0 } ] },
      "streamSettings": { "network": "ws", "security": "none" } },
    { "tag": "vmess-grpc", "listen": "127.0.0.1", "port": 10012, "protocol": "vmess",
      "settings": { "clients": [ { "id": "$UUID", "alterId": 0 } ] },
      "streamSettings": { "network": "grpc", "security": "none", "grpcSettings": { "serviceName": "vmess" } } },
    { "tag": "trojan-ws",  "listen": "127.0.0.1", "port": 10003, "protocol": "trojan",
      "settings": { "clients": [ { "password": "$TROJAN_PASS" } ] },
      "streamSettings": { "network": "ws", "security": "none" } },
    { "tag": "trojan-grpc","listen": "127.0.0.1", "port": 10013, "protocol": "trojan",
      "settings": { "clients": [ { "password": "$TROJAN_PASS" } ] },
      "streamSettings": { "network": "grpc", "security": "none", "grpcSettings": { "serviceName": "trojan" } } },
    { "tag": "ss-tcp",     "listen": "127.0.0.1", "port": 10004, "protocol": "shadowsocks",
      "settings": { "method": "$SS_METHOD", "password": "$SS_PASS", "network": "tcp,udp" } },
    { "tag": "ss-grpc",    "listen": "127.0.0.1", "port": 10014, "protocol": "shadowsocks",
      "settings": { "method": "$SS_METHOD", "password": "$SS_PASS", "network": "tcp,udp" },
      "streamSettings": { "network": "grpc", "security": "none", "grpcSettings": { "serviceName": "ss" } } }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
XRAYEOF

# validate before we ever restart the service
/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1 \
  || die "xray config failed validation"

cat > /etc/systemd/system/xray.service <<'UNIT'
[Unit]
Description=Xray Service
Documentation=https://xtls.github.io/
After=network.target nss-lookup.target

[Service]
User=xray
Group=xray
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
UMask=0077
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
RuntimeDirectory=xray
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable xray >/dev/null 2>&1 || true
ok "xray config valid + unit installed"

# --- 4. badvpn -------------------------------------------------------------
log "4/11 badvpn-udpgw (built from source)"
if [ ! -x /usr/local/bin/badvpn-udpgw ]; then
  tmp=$(mktemp -d)
  git clone --depth 1 https://github.com/ambrop72/badvpn.git "$tmp/badvpn" >/dev/null 2>&1
  ( cd "$tmp/badvpn" \
    && mkdir -p build && cd build \
    && cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_BADVPN-UDPGW=1 >/dev/null 2>&1 \
    && make -j"$(nproc)" >/dev/null 2>&1 \
    && install -m 755 badvpn-udpgw /usr/local/bin/badvpn-udpgw )
  rm -rf "$tmp"
fi
[ -x /usr/local/bin/badvpn-udpgw ] || die "badvpn-udpgw build failed"
/usr/local/bin/badvpn-udpgw --help 2>&1 | head -1 | sed 's/^/    /' || true
ok "badvpn ready"

cat > /etc/systemd/system/badvpn-udpgw@.service <<'UNIT'
[Unit]
Description=badvpn UDP gateway on port %i
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:%i --max-clients 512
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
for p in 7100 7200 7300 7400 7500 7600 7700 7800 7900; do
  systemctl enable --now "badvpn-udpgw@${p}.service" >/dev/null 2>&1 || true
done
ok "badvpn units 7100-7900 enabled"

# --- 5. TLS certs ----------------------------------------------------------
log "5/11 certificates"
# nginx/stunnel front cert: fresh, with THIS box's IP in the SAN.
# (capture first — `openssl | grep -q` would SIGPIPE openssl under pipefail)
CERT_TXT="$(openssl x509 -in /etc/nginx/pulse.crt -noout -text 2>/dev/null || true)"
if ! grep -q "IP Address:${IP}" <<<"$CERT_TXT"; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout /etc/nginx/pulse.key -out /etc/nginx/pulse.crt \
    -subj "/CN=PulseTunnel" \
    -addext "subjectAltName=IP:${IP},DNS:localhost,DNS:pulse.local" >/dev/null 2>&1
  chmod 600 /etc/nginx/pulse.key
  ok "nginx front cert issued for ${IP}"
else
  ok "nginx front cert already valid for ${IP}"
fi
install -d -m 755 /etc/stunnel
cp -f /etc/nginx/pulse.crt /etc/stunnel/pulse.crt
cp -f /etc/nginx/pulse.key /etc/stunnel/pulse.key
chmod 600 /etc/stunnel/pulse.key

# --- 6. nginx --------------------------------------------------------------
log "6/11 nginx (stream SNI router + WS/gRPC locations)"
cat > /etc/nginx/sites-available/pulse <<'NGINX'
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

# TLS backend reached via the stream SNI router on 443
server {
    listen 127.0.0.1:10443 ssl;
    http2 on;
    server_name _;
    ssl_certificate     /etc/nginx/pulse.crt;
    ssl_certificate_key /etc/nginx/pulse.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    include /etc/nginx/pulse-locations.conf;
}

# Plain HTTP on 80: VLESS/VMess/Trojan WS none-TLS + SSH WS + gRPC
server {
    listen 80 default_server;
    server_name _;
    include /etc/nginx/pulse-locations.conf;
}

# Spec port 81
server {
    listen 81;
    server_name _;
    location / {
        return 200 "Pulse Tunnel nginx :81 OK\n";
        add_header Content-Type text/plain;
    }
}
NGINX

cat > /etc/nginx/pulse-locations.conf <<'LOC'
# ---- VLESS over WebSocket ----
location = /fnfgcp {
    proxy_pass http://127.0.0.1:10001/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
location = /tyxyws {
    proxy_pass http://127.0.0.1:10001/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
# ---- VLESS over XHTTP ----
location = /xhttp_vless_juan {
    proxy_pass http://127.0.0.1:10021/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
# ---- VMess / Trojan over WebSocket ----
location = /vmess {
    proxy_pass http://127.0.0.1:10002/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
location = /trojan {
    proxy_pass http://127.0.0.1:10003/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
# ---- SSH over WebSocket ----
location = /ssh {
    proxy_pass http://127.0.0.1:10080/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
# ---- gRPC (HTTP/2) ----
location /vless/ {
    grpc_pass grpc://127.0.0.1:10011;
    grpc_set_header X-Real-IP $remote_addr;
}
location /vmess/ {
    grpc_pass grpc://127.0.0.1:10012;
    grpc_set_header X-Real-IP $remote_addr;
}
location /trojan/ {
    grpc_pass grpc://127.0.0.1:10013;
    grpc_set_header X-Real-IP $remote_addr;
}
location /ss/ {
    grpc_pass grpc://127.0.0.1:10014;
    grpc_set_header X-Real-IP $remote_addr;
}
# ---- default ----
location / {
    return 200 "Pulse Tunnel\n";
    add_header Content-Type text/plain;
}
LOC

mkdir -p /etc/nginx/stream.d
cat > /etc/nginx/stream.d/sni.conf <<'SNI'
map $ssl_preread_server_name $pulse_backend {
    ""        127.0.0.1:10004;   # no SNI  -> Shadowsocks (raw TCP, app sends no TLS)
    default   127.0.0.1:10443;   # SNI     -> nginx HTTPS (VLESS/VMess/Trojan/SSH-WS/gRPC)
}

server {
    listen 443;
    ssl_preread on;
    proxy_pass $pulse_backend;
    proxy_connect_timeout 5s;
    proxy_timeout 10m;
}
SNI

ln -sfn /etc/nginx/sites-available/pulse /etc/nginx/sites-enabled/pulse

# make sure the stream block exists exactly once
if ! grep -qE '^\s*stream\s*\{' /etc/nginx/nginx.conf; then
  cat >> /etc/nginx/nginx.conf <<'STREAM'

stream {
    include /etc/nginx/stream.d/*.conf;
}
STREAM
  ok "stream block appended to nginx.conf"
fi
nginx -t >/dev/null 2>&1 || die "nginx config test failed"
ok "nginx config valid"

# --- 7. stunnel ------------------------------------------------------------
log "7/11 stunnel4 (222, 777 -> sshd)"
cat > /etc/stunnel/stunnel.conf <<'STUNNEL'
pid = /run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4
debug = 4

[ssh-222]
accept  = 222
connect = 127.0.0.1:22
cert    = /etc/stunnel/pulse.crt
key     = /etc/stunnel/pulse.key

[ssh-777]
accept  = 777
connect = 127.0.0.1:22
cert    = /etc/stunnel/pulse.crt
key     = /etc/stunnel/pulse.key
STUNNEL
mkdir -p /run/stunnel4
chown stunnel4:stunnel4 /run/stunnel4 2>/dev/null || true
ok "stunnel config written"

# --- 8. ssh over websocket -------------------------------------------------
log "8/11 websockify (SSH over WS on 10080)"
cat > /etc/systemd/system/ssh-ws.service <<'UNIT'
[Unit]
Description=SSH over WebSocket bridge
After=network.target ssh.service

[Service]
ExecStart=/usr/bin/websockify 127.0.0.1:10080 127.0.0.1:22
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now ssh-ws.service >/dev/null 2>&1 || true
ok "ssh-ws enabled"

# --- 9. openvpn ------------------------------------------------------------
log "9/11 openvpn (8443 tcp + 1194 udp)"
OVPN_DIR=/etc/openvpn
PKI_DIR=$OVPN_DIR/pulse-pki
mkdir -p "$PKI_DIR/pki/issued" "$PKI_DIR/pki/private"

if [ -n "$PKI_B64" ]; then
  tmp=$(mktemp -d)
  printf '%s' "$PKI_B64" | base64 -d > "$tmp/pki.tgz" 2>/dev/null \
    && tar xzf "$tmp/pki.tgz" -C "$tmp" 2>/dev/null
  if [ -f "$tmp/ca.crt" ] && [ -f "$tmp/server.crt" ] && [ -f "$tmp/server.key" ]; then
    install -m 644 "$tmp/ca.crt"    "$PKI_DIR/pki/ca.crt"
    install -m 644 "$tmp/server.crt" "$PKI_DIR/pki/issued/server.crt"
    install -m 600 "$tmp/server.key" "$PKI_DIR/pki/private/server.key"
    ok "reused the shipped CA so existing client profiles keep verifying"
  else
    warn "--pki-b64 supplied but unreadable — generating a fresh CA instead"
    PKI_B64=""
  fi
  rm -rf "$tmp"
fi

if [ ! -f "$PKI_DIR/pki/ca.crt" ]; then
  log "    generating a fresh OpenVPN CA"
  command -v easyrsa >/dev/null 2>&1 && EASYRSA="$(command -v easyrsa)" \
    || EASYRSA=/usr/share/easy-rsa/easyrsa
  ( cd "$PKI_DIR" \
    && "$EASYRSA" init-pki --batch >/dev/null 2>&1 \
    && "$EASYRSA" build-ca --batch nopass >/dev/null 2>&1 \
    && "$EASYRSA" build-server-full --batch server nopass >/dev/null 2>&1 )
  [ -f "$PKI_DIR/pki/ca.crt" ] || die "OpenVPN CA generation failed"
  ok "fresh CA generated (REPOINT WILL NEED TO RE-EMBED IT)"
fi

cat > "$OVPN_DIR/check_auth.sh" <<'AUTH'
#!/bin/sh
# via-file: $1 = temp file, line1=username, line2=password
U=$(sed -n 1p "$1" 2>/dev/null)
P=$(sed -n 2p "$1" 2>/dev/null)
[ -n "$U" ] && [ -n "$P" ] || exit 1
grep -qxF "${U}:${P}" /etc/openvpn/pulse-users
AUTH
chmod 755 "$OVPN_DIR/check_auth.sh"
echo 'pulse:a0Q8W7FtyytEwOjZ' > "$OVPN_DIR/pulse-users"
chmod 600 "$OVPN_DIR/pulse-users"

write_ovpn() { # $1=conf  $2=port  $3=proto  $4=subnet  $5=status
  cat > "$OVPN_DIR/server/$1" <<CONF
port $2
proto $3
dev tun
ca $PKI_DIR/pki/ca.crt
cert $PKI_DIR/pki/issued/server.crt
key $PKI_DIR/pki/private/server.key
dh none
ecdh-curve prime256v1
verify-client-cert none
username-as-common-name
script-security 2
auth-user-pass-verify /etc/openvpn/check_auth.sh via-file
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
server $4 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
verb 3
status $5
CONF
}
mkdir -p "$OVPN_DIR/server"
write_ovpn pulse.conf     8443 tcp-server 10.8.0.0 /var/log/openvpn-pulse-status.log
write_ovpn pulse1194.conf 1194 udp        10.8.1.0 /var/log/openvpn-pulse1194-status.log
systemctl enable openvpn-server@pulse >/dev/null 2>&1 || true
systemctl enable openvpn-server@pulse1194 >/dev/null 2>&1 || true
ok "openvpn configs written"

# --- 10. kernel + firewall -------------------------------------------------
log "10/11 ip_forward + iptables"
mkdir -p /etc/sysctl.d
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-pulse-forward.conf
sysctl -p /etc/sysctl.d/99-pulse-forward.conf >/dev/null 2>&1 || true

mkdir -p /etc/iptables
IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}' || true)"
[ -n "$IFACE" ] || IFACE=eth0
cat > /etc/iptables/rules.v4 <<RULES
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -i tun+ -o $IFACE -j ACCEPT
-A FORWARD -i $IFACE -o tun+ -j ACCEPT
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/24 -o $IFACE -j MASQUERADE
-A POSTROUTING -s 10.8.1.0/24 -o $IFACE -j MASQUERADE
COMMIT
RULES
iptables-restore < /etc/iptables/rules.v4 2>/dev/null || true

cat > /etc/rc.local <<'RC'
#!/bin/sh -e
[ -f /etc/iptables/rules.v4 ] && iptables-restore < /etc/iptables/rules.v4
exit 0
RC
chmod 755 /etc/rc.local
ok "forwarding + NAT masquerade on $IFACE"

# --- 11. start everything --------------------------------------------------
log "11/11 starting services"
systemctl daemon-reload
for u in nginx stunnel4 xray ssh-ws openvpn-server@pulse openvpn-server@pulse1194; do
  systemctl enable "$u" >/dev/null 2>&1 || true
  systemctl restart "$u" >/dev/null 2>&1 || warn "restart $u"
done
for p in 7100 7200 7300 7400 7500 7600 7700 7800 7900; do
  systemctl restart "badvpn-udpgw@${p}.service" >/dev/null 2>&1 || true
done
sleep 3

# --- verify ----------------------------------------------------------------
if [ "$SKIP_VERIFY" = "1" ]; then
  log "install finished (--skip-verify)"
  exit 0
fi

log "verifying listeners"
FAIL=0
check_tcp() {
  local p="$1" label="$2" out
  # capture first: `ss | grep -q` makes grep exit early and SIGPIPE ss
  out="$(ss -tlnH 2>/dev/null || true)"
  if grep -qE "[:.]$p\b" <<<"$out"; then ok "TCP $p  $label"; else warn "TCP $p  $label MISSING"; FAIL=1; fi
}
check_udp() {
  local p="$1" label="$2" out
  out="$(ss -ulnH 2>/dev/null || true)"
  if grep -qE "[:.]$p\b" <<<"$out"; then ok "UDP $p  $label"; else warn "UDP $p  $label MISSING"; FAIL=1; fi
}
check_tcp 22   "OpenSSH"
check_tcp 80   "nginx WS none-TLS"
check_tcp 81   "nginx"
check_tcp 443  "nginx stream SNI router"
check_tcp 222  "stunnel4 -> sshd"
check_tcp 777  "stunnel4 -> sshd"
check_tcp 8443 "OpenVPN tcp"
check_tcp 7100 "badvpn"; check_tcp 7200 "badvpn"; check_tcp 7300 "badvpn"
check_tcp 7400 "badvpn"; check_tcp 7500 "badvpn"; check_tcp 7600 "badvpn"
check_tcp 7700 "badvpn"; check_tcp 7800 "badvpn"; check_tcp 7900 "badvpn"
check_udp 1194 "OpenVPN udp"
for p in 10001 10002 10003 10004 10011 10012 10013 10014 10021; do
  check_tcp "$p" "xray inbound"
done
check_tcp 10080 "websockify (SSH over WS)"
check_tcp 10443 "nginx TLS backend"

echo
if [ "$FAIL" = "0" ]; then
  log "ALL PORTS ACTIVE on $IP"
else
  log "SOME PORTS MISSING — see warnings above"
fi

echo
log "service states"
for u in nginx stunnel4 xray ssh-ws openvpn-server@pulse openvpn-server@pulse1194; do
  printf '  %-34s %s\n' "$u" "$(systemctl is-active "$u" 2>&1)"
done
printf '  %-34s %s\n' "badvpn instances" "$(systemctl is-active badvpn-udpgw@7100 2>&1)"

exit "$FAIL"
