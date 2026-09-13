# bin/ — local binaries (not tracked)

This directory holds local-only binaries and assets; everything here is
gitignored except this file and the upstream `LICENSE*` copies:

- `xray.exe` / `xray` — Xray-core (L3 probe)
- `geoip.dat`, `geosite.dat` — Xray routing assets
- `wintun.dll` — Windows TUN driver (only needed for TUN mode, not the probe)
- `data/GeoLite2-Country.mmdb` lives in `../data/` (gitignored too)

CI downloads its own pinned copies (see `.github/workflows/update.yml`,
checksum-verified via `.github/xray.sha256` / `.github/singbox.sha256`).
Never commit binaries here.

## Local layout

- Windows: `XRAY_EXECUTABLE=bin/xray.exe` (flat), assets next to it
  (`XRAY_LOCATION_ASSET=bin`).
- Linux/CI: `bin/xray/xray` and `bin/singbox/sing-box` (subdirs created by
  the workflow unpack step).

## Upstream

Xray-core comes from [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
(Mozilla Public License 2.0 — see `LICENSE`). The upstream Project X README
(including its donation addresses) is *not* kept in this repository; refer to
the upstream repo for sponsors/donations — those wallet addresses belong to
the XTLS project, not to this deployment.
