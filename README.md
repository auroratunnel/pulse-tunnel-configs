# pulse-tunnel-configs

Public configuration delivery repo for **Pulse Tunnel**.

This repository is written to **only** by the Pulse Tunnel admin panel
(Cloudflare Worker `pulse-tunnel-admin`) and read by the Android app.

| File | Purpose |
|---|---|
| `pulse_configs_2026_v2.enc` | Encrypted server/config bundle (AES-GCM ciphertext) |
| `pulse_app_settings.enc` | Encrypted settings bundle (lock / force-update / branding) |
| `manifest.json` | Publish manifest (file hashes + timestamps) |
| `<deviceId>.json` | Per-device trial/VIP status mirror |

Everything except `README.md`/`manifest.json` is **ciphertext** — publishing
this repo publicly leaks no configuration, and it lets the app download
bundles from the GitHub Pages CDN instead of the admin Worker (which keeps the
Worker inside the Cloudflare Free plan limits).

Download base URL (`CONFIG_RAW_BASE`):
`https://auroratunnel.github.io/pulse-tunnel-configs`

## Installable builds

GitHub **Releases** on this repo carry the signed APKs produced by the
`Build Android APK` workflow of the private source repo, so end users can
install Pulse Tunnel without GitHub access:

- arm64-v8a (most modern phones)
- armeabi-v7a (older/entry-level phones)

Release assets live outside the branch tree, so they never interfere with the
config files the app downloads above.
