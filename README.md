# VPN Config Parser

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/Moonishe/vpnparser/update.yml?branch=main&label=CI&logo=github" alt="CI">
  <img src="https://img.shields.io/badge/python-%3E%3D3.11-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/github/license/Moonishe/vpnparser" alt="License">
  <img src="https://img.shields.io/github/last-commit/Moonishe/vpnparser" alt="Last commit">
</p>

Fetches public VPN proxy configurations from GitHub sources, parses supported
protocol links, filters & deduplicates them, runs liveness checks (TCP/TLS/Xray
L3 probe), then publishes Happ/v2ray-compatible base64 subscriptions.

---

## Pipeline

```
fetch ──► parse ──► garbage filter ──► dedup ──► country filter
                                                │
                                                ▼
                                         aggregate ──► write ──► publish
```

1. **Fetch** — downloads subscription files from configured GitHub repos and URLs.
2. **Parse** — extracts proxy links (`vmess://`, `vless://`, `trojan://`, …), decodes base64 blobs.
3. **Garbage filter** — drops malformed or obviously invalid configs.
4. **Dedup** — removes duplicates by `(protocol, address, port)`.
5. **Country filter** — keeps only allowed countries, applies per-list rules.
6. **Aggregate** — country-balanced round-robin selection caps per output.
7. **Write** — produces base64-encoded subscription files.
8. **Publish** — pushes outputs to a configured GitHub repository.

### Network validation

GitHub Actions runners often cannot reach VPN servers directly, so the
validator can build a small SOCKS5 proxy pool from public proxy lists and
route checks through it:

| Check | What it proves |
|-------|---------------|
| TCP | Port is open |
| TLS | TLS handshake succeeds (uses SNI / Host from config) |
| Xray L3 | Full proxied HTTPS request through the actual protocol |

Each config is tried through multiple SOCKS5 proxies before being marked
unreachable. If too few proxies are found, the search widens across
candidate lists for several rounds. Production settings use **fail-closed**
mode: weak validation publishes fewer configs instead of putting unchecked
ones back into subscriptions.

### Output files

| File | Contents |
|------|----------|
| `output/subscription.txt` | Combined pool (country-balanced, ~200 configs) |
| `output/subscription-blacklist.txt` | Blacklist pool |
| `output/subscription-whitelist.txt` | Whitelist / restricted-network pool |
| `output/subscription-mix.txt` | 100 black + 100 white |
| `output/locations/subscription-XX.txt` | Per-country subsets (≤50 per country) |
| `output/run-summary.json` | Validation metadata for Telegram notifications |

---

## Sources

Sources are configured in [`config/sources.json`](config/sources.json).

Each source supports:

| Field | Description |
|-------|-------------|
| `type` | `subscription` (single file), `raw` (directory), `url` (direct HTTPS) |
| `list_type` | `blacklist`, `whitelist`, or `mixed` |
| `owner`, `repo`, `path`, `branch` | GitHub source location |
| `url` | Direct URL (for `url` type) |
| `default_country` | Fallback when country detection fails |
| `max_depth`, `max_files`, `include_files`, `exclude_files` | Directory crawl options |

### Included upstreams

- **igareck/vpn-configs-for-russia** — Black + White lists
- **luxxuria/harvester** — Top tested configs
- **DarkRoyalty/shnajder-vpn-configs** — Whitelist entries
- **V2RayRoot/V2RayConfig**, **sakha1370/OpenRay** — Blacklist pools
- **jsxta/whitelist-russia** — Whitelist subscription
- **proxifly/free-proxy-list**, **ProxyScrape/free-proxy-list**, **VPSLabCloud/VPSLab-Free-Proxy-List**, **gfpcom/free-proxy-list** — SOCKS5 proxy pool

---

## Supported Protocols

| Protocol | Schemes |
|----------|---------|
| VMess | `vmess://` |
| VLESS | `vless://` |
| Trojan | `trojan://` |
| Shadowsocks | `ss://` |
| Hysteria2 | `hysteria2://`, `hy2://` |
| TUIC | `tuic://` |
| ShadowTLS | `shadowtls://` |
| AnyTLS | `anytls://` |

---

## Setup

```bash
# Production dependencies
pip install -e .

# Development dependencies (lint, typecheck, tests, security)
pip install -e ".[dev]"

# Optional: pre-commit hooks
pre-commit install
```

### Environment

Local `.env` files are loaded automatically when `python-dotenv` is installed.

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub API token (unauthenticated rate limits are tight) |
| `GITHUB_OWNER` | Repository owner for publishing |
| `GITHUB_REPO` | Repository name for publishing |
| `GITHUB_BRANCH`| Branch for publishing (default: `main`) |
| `LLM_API_KEY` | DashScope Qwen key for LLM fallback parsing |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token for notifications |
| `TELEGRAM_CHAT_ID` | Target chat ID for notifications |
| `VALIDATOR_PROXY` | Optional HTTP proxy for validation |

---

## Usage

```bash
# Run pipeline (fetch → validate → write, no publish)
python -m src.main --run

# Run and publish results
python -m src.main --run --publish

# Verbose mode
python -m src.main --run -v
```

### Tests

```bash
python -m pytest -q -p no:cacheprovider
```

---

## Configuration

Key settings in [`config/settings.yaml`](config/settings.yaml):

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `sources` | `max_concurrent_fetches` | `10` | Concurrent fetch limit |
| `validator` | `allowed_countries` | `[]` | Global country allowlist (empty = all) |
| `validator` | `allowed_countries_by_list` | `–` | Per-list country overrides |
| `validator` | `whitelist_ru_ratio`, `whitelist_eu_countries` | `0.8` | RU/EU split in whitelist |
| `validator` | `max_configs_to_validate` | `0` | Cap on parsed configs (0 = unlimited) |
| `validator` | `tcp_enabled`, `tls_enabled`, `xray_enabled` | `true` | Liveness check toggles |
| `validator` | `proxy_attempts_per_config`, `tls_proxy_attempts_per_config` | `3` | SOCKS5 proxy retries |
| `validator` | `xray_max_alive_by_list`, `xray_concurrency` | `200`, `20` | Xray probe limits |
| `validator` | `require_distinct_outbound_ip` | `false` | Fail-closed when direct IP unknown |
| `validator` | `min_alive_to_filter`, `fail_open_on_low_alive` | `10`, `false` | Low-live thresholds |
| `aggregator` | `max_configs_in_output` | `200` | Hard cap per file |
| `aggregator` | `max_per_country` | `50` | Per-country cap |
| `publisher` | `output_file` | `output/subscription.txt` | Combined output path |
| `llm` | `enabled` | `false` | LLM fallback when regex finds no links |

---

## GitHub Actions

[`.github/workflows/update.yml`](.github/workflows/update.yml) runs:

- **Schedule:** every hour
- **Triggers:** manual dispatch, pushes touching pipeline code

It installs dependencies, runs tests, executes the pipeline, publishes
subscription files, and sends an optional Telegram notification with a
summary and a fun VPN fact.

---

## Notes

- Output files are base64-encoded subscriptions containing newline-separated
  raw proxy links.
- Each output starts with a harmless VMess watermark entry for client
  identification.
- Fetch failures are isolated per source — one dead upstream does not fail
  the whole run.
- Blacklist output keeps only `DE`, `FI`, `NL`, `US`, `GB`, `FR`, `JP`, `CA`.
- Whitelist targets 200 checked configs with an 80% RU / 20% EU split.
- LLM fallback ([DashScope Qwen](https://dashscope.aliyun.com)) can extract
  links from pages where regex parsing fails.
