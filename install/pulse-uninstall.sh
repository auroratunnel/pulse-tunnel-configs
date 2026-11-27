#!/usr/bin/env bash
# =============================================================================
# pulse-uninstall.sh — remove the Pulse Tunnel stack from this VPS.
#
# The inverse of pulse-install.sh, held to the same rules:
#   * IDEMPOTENT — safe on a box that was never (fully) installed: every step
#     checks before it acts, a missing file/unit is not an error, and the
#     script still reaches its verdict.
#   * SSH IS NEVER TOUCHED. OpenSSH (22) is what the panel needs to reach the
#     box again for a future install, so nothing here stops, disables, edits
#     or removes sshd or anything it reads. The verification below proves
#     ssh.service is active AND port 22 still listens; if either fails the
#     run reports UNINSTALL INCOMPLETE instead of success.
#   * Only files this stack writes are removed. Package files (nginx's stock
#     default site, the rest of /etc/nginx/nginx.conf, …) are restored or left
#     alone — never deleted wholesale.
#   * apt packages stay installed. nginx/openvpn/stunnel4/websockify are inert
#     without our configs, and purging them risks the box for no gain;
#     re-running pulse-install.sh restores the whole stack anyway.
#
# Usage — the same shape as the installer so the workflow passes ONE command
# line for both modes. --pki-b64 and --skip-verify are accepted and ignored
# (a manual dispatch may carry them; nothing here needs them):
#   pulse-uninstall.sh --ip <public-ip>
#
# Verdict (the workflow polls for exactly these strings):
#   PULSE UNINSTALLED      — our services stopped, our files gone, SSH alive.
#   UNINSTALL INCOMPLETE   — see the FAIL lines above it.
# =============================================================================
set -Eeuo pipefail

IP=""
SKIP_VERIFY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ip)          IP="${2:-}"; shift 2 ;;
    --pki-b64)     shift 2 ;;            # accepted so both modes share a command line
    --skip-verify) SKIP_VERIFY=1; shift ;;
    -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

_T0=$(date +%s)
_TL=$_T0
log()  {
  local t; t=$(date +%s)
  printf '\033[1;36m[pulse:uninstall]\033[0m %s  \033[2m(+%ss, total %ss)\033[0m\n' \
    "$*" "$((t - _TL))" "$((t - _T0))"
  _TL=$t
}
ok()   { printf '  \033[1;32mOK\033[0m   %s\n' "$*"; }
warn() { printf '  \033[1;33mWARN\033[0m %s\n' "$*"; }
die()  {
  printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2
  # The workflow polls the log for this verdict, exactly as it does for the
  # installer — emitting it here makes a failure surface in seconds instead
  # of after the poll window, while still showing the real reason above.
  printf 'UNINSTALL INCOMPLETE — aborted: %s\n' "$*"
  exit 1
}

on_abort() {
  printf '  \033[1;31mFAIL\033[0m unexpected error (exit %s) at line %s\n' "$2" "$1" >&2
  printf 'UNINSTALL INCOMPLETE — unexpected error at line %s\n' "$1"
}
trap 'on_abort "$LINENO" "$?"' ERR

# --- preflight ---------------------------------------------------------------
[ "$(id -u)" = "0" ] || die "must run as root"
log "removing the Pulse stack${IP:+ from $IP}"

# Whether WE put unbound on port 53 (pulse-install.sh only does that when53
# was free). Captured before the config is deleted: a provider box may run its
# own DNS on 53, which was never ours to remove.
OWED_DNS=0
if [ -f /etc/unbound/unbound.conf.d/pulse.conf ]; then OWED_DNS=1; fi

# --- stop services -----------------------------------------------------------
# Stopped unconditionally rather than "only if we configured it": the panel
# only runs this against a box it installed on, and a half-failed install
# (apt done, configs never written) leaves nginx serving its stock welcome
# page on :80 — which would otherwise survive an uninstall.
#
# None of these is sshd. ssh-ws is a websockify bridge that merely forwards
# TO sshd; stunnel4 terminates TLS on 222/777 and forwards to sshd; stopping
# either changes nothing about the SSH daemon itself. OpenSSH is not in this
# list and never will be.
log "stopping services"
SVC=(
  xray ssh-ws stunnel4 nginx unbound
  openvpn-server@pulse openvpn-server@pulse1194
)
# disable and stop are two separate calls, mirroring how the installer starts
# them (enable, then restart). A combined `disable --now` proved NOT to stop
# the SysV-wrapped stunnel4 unit on the reference box — it stayed active and
# failed verification.
for u in "${SVC[@]}"; do
  systemctl disable "$u" >/dev/null 2>&1 || true
  systemctl stop "$u" >/dev/null 2>&1 || true
done
for p in 7100 7200 7300 7400 7500 7600 7700 7800 7900; do
  systemctl disable "badvpn-udpgw@${p}.service" >/dev/null 2>&1 || true
  systemctl stop "badvpn-udpgw@${p}.service" >/dev/null 2>&1 || true
done
systemctl reset-failed >/dev/null 2>&1 || true

# A unit can go inactive while its daemon lives on: systemd-sysv-generator
# gives stunnel4 KillMode=process with GuessMainPID=no, so systemd has nothing
# to kill and the init script's stop misses the pidfile — observed on the
# reference box (unit inactive, /usr/bin/stunnel4 still holding 222/777).
# Sweep by exact process name; only processes this stack creates match.
for p in stunnel4 xray badvpn-udpgw openvpn; do
  pkill -x "$p" >/dev/null 2>&1 || true
done
ok "services stopped and disabled, leftover daemons swept"

# --- unit files --------------------------------------------------------------
log "removing unit files"
rm -f /etc/systemd/system/xray.service \
      /etc/systemd/system/ssh-ws.service \
      /etc/systemd/system/badvpn-udpgw@.service
systemctl daemon-reload
ok "units removed, daemon reloaded"

# --- nginx -------------------------------------------------------------------
# Only OUR files: the pulse site, its location map, the stream SNI router and
# the front certificate. nginx.conf itself is never rewritten wholesale — only
# the stream block this installer appended (identified by its stream.d include
# line, which no stock or provider config has) is dropped.
log "nginx"
rm -f /etc/nginx/sites-enabled/pulse \
      /etc/nginx/sites-available/pulse \
      /etc/nginx/pulse-locations.conf \
      /etc/nginx/stream.d/sni.conf \
      /etc/nginx/pulse.crt \
      /etc/nginx/pulse.key
rmdir /etc/nginx/stream.d 2>/dev/null || true

if [ -f /etc/nginx/nginx.conf ] && grep -qF 'include /etc/nginx/stream.d/*.conf;' /etc/nginx/nginx.conf; then
  inc=$(grep -nF 'include /etc/nginx/stream.d/*.conf;' /etc/nginx/nginx.conf | sed -n '1s/:.*//p')
  if [ -n "$inc" ] && [ "$inc" -gt 1 ] \
     && sed -n "$((inc - 1))p" /etc/nginx/nginx.conf | grep -q '^stream[[:space:]]*{'; then
    # Delete exactly our block: the `stream {` line, the include, the `}`.
    # sed -i keeps the file's original mode/owner (an awk+mv rewrite would not).
    sed -i "$((inc - 1)),$((inc + 1))d" /etc/nginx/nginx.conf
    ok "removed the appended stream block"
  else
    warn "stream.d include found but no matching stream { above it — left alone"
  fi
fi

# The installer deletes sites-enabled/default (its `listen 80 default_server`
# collides with the pulse site). Put the stock symlink back so nginx is stock
# again for whatever comes next.
if [ ! -e /etc/nginx/sites-enabled/default ] && [ -e /etc/nginx/sites-available/default ]; then
  ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
  ok "stock nginx default site re-enabled"
fi
ok "nginx pulse config removed"

# --- stunnel -----------------------------------------------------------------
# stunnel.conf is the package's own file, overwritten by the installer, so the
# stock copy cannot come back without an apt reinstall — the file is simply
# removed and the unit stays disabled (nothing starts it on a clean box).
log "stunnel"
rm -f /etc/stunnel/stunnel.conf /etc/stunnel/pulse.crt /etc/stunnel/pulse.key
ok "stunnel config removed"

# --- xray --------------------------------------------------------------------
log "xray"
rm -rf /usr/local/etc/xray /var/lib/xray
rm -f /usr/local/bin/xray
if id xray >/dev/null 2>&1; then
  userdel xray >/dev/null 2>&1 || true
fi
ok "xray binary, config and system user removed"

# --- badvpn ------------------------------------------------------------------
log "badvpn"
rm -f /usr/local/bin/badvpn-udpgw
ok "badvpn-udpgw removed"

# --- openvpn -----------------------------------------------------------------
# Includes the PKI (ca.crt/server.key) and the user file: this box is leaving
# the fleet, so no private material is left behind. The panel's client
# profiles are unaffected — each carries its own copy of the CA.
log "openvpn"
rm -f /etc/openvpn/server/pulse.conf \
      /etc/openvpn/server/pulse1194.conf \
      /etc/openvpn/check_auth.sh \
      /etc/openvpn/pulse-users \
      /var/log/openvpn-pulse-status.log \
      /var/log/openvpn-pulse1194-status.log
rm -rf /etc/openvpn/pulse-pki
ok "openvpn configs, users and PKI removed"

# --- unbound -----------------------------------------------------------------
log "dns"
rm -f /etc/unbound/unbound.conf.d/pulse.conf
ok "unbound pulse ACL removed"

# --- kernel + firewall -------------------------------------------------------
# Our sysctl drop-in goes, then `sysctl --system` re-applies whatever the OS
# and the provider define. Deliberately NOT forcing ip_forward=0: a provider
# image may legitimately want it on, and with no tun devices and no rules
# left it forwards nothing anyway.
log "kernel + firewall"
rm -f /etc/sysctl.d/99-pulse-forward.conf
sysctl --system >/dev/null 2>&1 || true

# Only OUR iptables rules (the tun+ / 10.8.x MASQUERADE lines this installer
# writes) are deleted; every other rule on the box is untouched. The loops
# clear duplicates too, and a missing rule just ends the loop.
IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}' || true)"
[ -n "$IFACE" ] || IFACE=eth0
while iptables -D FORWARD -i tun+ -o "$IFACE" -j ACCEPT 2>/dev/null; do :; done
while iptables -D FORWARD -i "$IFACE" -o tun+ -j ACCEPT 2>/dev/null; do :; done
while iptables -D POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null; do :; done
while iptables -D POSTROUTING -s 10.8.1.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null; do :; done

# rules.v4 and rc.local are only ours if they carry our markers (a provider
# image may ship its own of either).
if [ -f /etc/iptables/rules.v4 ] && grep -q '10.8.0.0/24' /etc/iptables/rules.v4; then
  rm -f /etc/iptables/rules.v4
fi
if [ -f /etc/rc.local ] && grep -q 'iptables-restore < /etc/iptables/rules.v4' /etc/rc.local; then
  rm -f /etc/rc.local
fi
ok "forwarding drop-in, our iptables rules and rc.local cleared"

# --- scratch files -----------------------------------------------------------
# The running script and its log stay put (the workflow is still reading
# them); everything else this stack dropped in /tmp goes — including the
# OpenVPN CA bundle, which holds a private key.
rm -f /tmp/pulse-install.sh /tmp/pulse-pki.tgz /tmp/pulse-install.log
ok "scratch files removed"

# --- verify ------------------------------------------------------------------
if [ "$SKIP_VERIFY" = "1" ]; then
  log "PULSE UNINSTALLED on ${IP:-this host} (--skip-verify: no checks run)"
  exit 0
fi

log "verifying"

# 1) SSH must have survived — the one thing that can never break. The panel
#    needs port 22 to reach this box for any future install.
if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
  ok "sshd service still active"
else
  die "sshd is NOT active — the box cannot be reached again"
fi
ss_out="$(ss -tlnH 2>/dev/null || true)"
if grep -qE ':22[[:space:]]' <<<"$ss_out"; then
  ok "TCP 22 still listening"
else
  die "TCP 22 is not listening"
fi

# 2) nothing of ours may still be running
for u in xray ssh-ws stunnel4 nginx unbound \
         openvpn-server@pulse openvpn-server@pulse1194 badvpn-udpgw@7100; do
  if systemctl is-active --quiet "$u" 2>/dev/null; then
    die "$u is still active"
  fi
done
ok "all stack services stopped"

# 2b) and no daemon of ours may still be a live process — a unit can be
#     inactive while its process survives (the SysV-wrapper case the sweep
#     above exists for). Every one of these also binds a port, so step 3 is
#     the backstop, but failing here names the culprit directly.
for p in stunnel4 xray badvpn-udpgw openvpn; do
  if pgrep -x "$p" >/dev/null 2>&1; then
    die "process $p is still running"
  fi
done
ok "no stack daemons left running"

# 3) none of our ports may still be bound (loopback included — xray and the
#    nginx TLS backend listen on 127.0.0.1 and count as "still installed")
for p in 80 81 443 8080 10443 222 777 8443 \
         7100 7200 7300 7400 7500 7600 7700 7800 7900 \
         10001 10002 10003 10004 10011 10012 10013 10014 10021 10080; do
  if grep -qE "[:.]${p}[[:space:]]" <<<"$ss_out"; then
    die "TCP $p is still listening"
  fi
done
uout="$(ss -ulnH 2>/dev/null || true)"
if grep -qE '[:.]1194[[:space:]]' <<<"$uout"; then
  die "UDP 1194 is still listening"
fi
ok "our TCP/UDP ports are free"

# 4) port 53 only if WE put unbound there. Loopback answers (systemd-resolved
#    on 127.0.0.53) do not count — only a listener on a routable address.
ext_listens() {
  local proto="$1" port="$2" out
  if [ "$proto" = tcp ]; then out="$(ss -tlnH 2>/dev/null || true)"
  else out="$(ss -ulnH 2>/dev/null || true)"; fi
  awk -v p=":$port" '
    $4 ~ p"$" && $4 !~ /^127\./ && $4 !~ /^\[::1\]/ { found=1 }
    END { exit !found }' <<<"$out"
}
if [ "$OWED_DNS" = "1" ]; then
  if ext_listens tcp 53 || ext_listens udp 53; then
    die "port 53 is still served from outside"
  fi
  ok "port 53 no longer served (we were the ones serving it)"
fi

echo
log "PULSE UNINSTALLED on ${IP:-this host}"
exit 0
