# Pulse Tunnel — VPS installer

One click in the admin panel provisions a fresh VPS with the entire
multi-protocol stack: every port and protocol in the spec, verified
port-by-port before the run is allowed to report success.

## How it runs

The panel is a Cloudflare Worker, and Workers have **no outbound TCP** — so it
cannot SSH anywhere itself. Instead:

```
panel "Install" button
   │  POST /api/install  { ip, password }
   ▼
Worker  ── repository_dispatch ──►  GitHub Actions  ── sshpass ──►  new VPS
   │                                    │
   └──── GET /api/install/status ◄──────┘   (run status + html_url)
```

- The password is sent to GitHub for the duration of the run and **never stored
  panel-side**; the panel keeps only run metadata.
- The shared OpenVPN CA lives in KV (`install_pki`), not the repo — the repo is
  public and the bundle contains `server.key`.
- Runs are serialised by the workflow's `concurrency` group, and the installer
  is fully idempotent, so re-clicking Install is harmless.

### Triggering it yourself

| Method | How |
|---|---|
| **Panel** | Install tab → IP + password → *Install all ports & protocols* |
| **API** | `POST /api/install` with session cookie + `x-csrf-token` |
| **CLI** | `workflow_dispatch` with `vps_ip`, `vps_password`, `pki_b64` |
| **Manual** | `bash install/pulse-install.sh --ip <ip> [--pki-b64 <b64>]` |

`--skip-verify` skips the listener sweep (useful when iterating).

## Ports

| Port | Service |
|---|---|
| 22 | OpenSSH |
| 80 / 443 | nginx — WS none-TLS / stream SNI router |
| 81 | nginx status page |
| 222, 777 | stunnel4 → sshd |
| 53 tcp+udp | unbound DNS (public queries **refused**) |
| 8080 | nginx alt-HTTP — same WS/gRPC locations as 80 |
| 7100–7900 | badvpn-udpgw (9 instances) |
| 8443 tcp / 1194 udp | OpenVPN |
| 10001–10021 | Xray inbounds |
| 10080 | websockify (SSH over WS) |
| 10443 | nginx TLS backend (loopback only) |

VLESS / VMess / Trojan / Shadowsocks are served over WS and gRPC on 80 and 443.

## Design decisions worth knowing

**443 is an nginx stream SNI router.** No SNI → `127.0.0.1:10004` (raw
Shadowsocks, the app sends no TLS). Any SNI → `127.0.0.1:10443`, where nginx
terminates TLS and routes to the WS/gRPC inbounds.

**OpenVPN is on 8443, not 443**, so the spec owns 443/80 for the proxy
protocols.

**53 binds the public IP, not `0.0.0.0`.** These boxes run systemd-resolved,
which already holds `127.0.0.53:53` — binding `0.0.0.0:53` fails with
`EADDRINUSE`, and `/etc/resolv.conf` must keep working. The ACL allows only
loopback, the host itself and the VPN subnets; **no `192.168.0.0/16` or
`172.16.0.0/12`**, because those cover the egress address of countless NAT/VPN
clients and would quietly re-create an open resolver. A blocklisted IP would
take the whole service down with it.

**The installer verifies locally; CI verifies from outside.** Local checks use
`ext_listens()`, which ignores `127.*`/`[::1]` — a naive "is :53 listening"
test matches systemd-resolved's loopback stub and reports the port open while
it is closed to the world. A separate workflow step then probes from GitHub's
network, the one vantage point a host cannot vouch for itself: ports must
answer a third party, and DNS must **REFUSED** a public source.

## Security notes on the workflow

GitHub prints an `env:` group at the start of **every** step, so any secret in
job-level env lands in the log before `::add-mask::` can register it. The
workflow therefore:

1. Runs **Mask credentials first, with no `env:` block at all**, reading values
   out of `$GITHUB_EVENT_PATH` with `jq`.
2. Keeps the password and PKI at **step level** on the two steps that need them
   — by then they render as `***`.
3. Never puts an expression opener inside a `run:` block. GitHub scans `run:`
   blocks for a dollar sign followed by two open braces, and an empty pair is
   a parse error for the *whole file* — which manifests as
   `repository_dispatch` returning 204 while scheduling nothing at all.

Verified: password and `pki_b64` appear **zero** times in clear across run logs.
