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
| `output/subscription.txt` | Combined pool (country-balanced, ≤`aggregator.max_configs_in_output`, currently 100) |
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
| `type` | `url` (direct HTTPS file), `url-list` (index file listing further URLs), `subscription` (single file in a GitHub repo), `raw` (directory in a GitHub repo) |
| `list_type` | `blacklist`, `whitelist`, or `mixed` |
| `url` | Direct URL (for `url` and `url-list`) |
| `owner`, `repo`, `path`, `branch` | GitHub source location (for `subscription` / `raw`) |
| `default_country` | Fallback when country detection fails |
| `timeout` | Per-request timeout in seconds |
| `max_depth`, `include_files`, `exclude_files` | Directory crawl options (`raw`) |
| `max_files` | Cap on fetched files: crawl depth for `raw`, URLs taken from the index for `url-list` (default 200) |
| `max_concurrent_urls` | Parallel fetches of the URLs listed by a `url-list` index (default 10) |

A `url-list` source fetches an index file and then every URL inside it, so the
targets are chosen by a third party. Those fetches are SSRF-guarded and size-
capped — see [SECURITY.md](SECURITY.md). All sources currently shipped are
`url` or `url-list`; none uses `owner`/`repo`.

### Included upstreams

- **igareck/vpn-configs-for-russia** — Black + White lists
- **luxxuria/harvester** — Top tested configs
- **DarkRoyalty/shnajder-vpn-configs** — Whitelist entries
- **V2RayRoot/V2RayConfig**, **sakha1370/OpenRay** — Blacklist pools
- **jsxta/whitelist-russia** — Whitelist subscription
- **kort0881/vpn-vless-configs-russia** — `url-list` indexes of mirrored blacklist sources
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
| `LLM_API_KEY` | Key for the provider in `llm.provider` (DashScope Qwen); fallback parsing is off by default |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token for notifications |
| `TELEGRAM_CHAT_ID` | Target chat ID for notifications |
| `VALIDATOR_PROXY` | Optional SOCKS5 proxy for validation |
| `XRAY_EXECUTABLE` | Xray-core binary for the L3 probe. Relative paths resolve from the project root, bare names from `PATH`. With `xray_required: true` and no binary the liveness stage drops everything |
| `XRAY_LOCATION_ASSET` | Directory with `geoip.dat`/`geosite.dat`, read by the Xray binary itself (optional) |

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
| `validator` | `xray_max_alive_by_list`, `xray_concurrency` | `200`, `5` | Xray probe limits |
| `validator` | `xray_required` | `true` | Drop everything when Xray cannot run (see `XRAY_EXECUTABLE`) |
| `validator` | `xray_require_distinct_outbound_ip` | `false` | Fail-closed when direct IP unknown |
| `validator` | `min_alive_to_filter`, `fail_open_on_low_alive` | `10`, `false` | Low-live thresholds |
| `validator` | `geoip_enabled` | `false` | IP→country enrichment via `geoip_api_url` |
| `validator` | `geoip_requests_per_minute`, `geoip_max_lookups` | `40`, `300` | GeoIP rate limit and per-run lookup cap (extra configs keep `country=None`) |
| `aggregator` | `max_configs_in_output` | `100` | Hard cap per file |
| `aggregator` | `max_per_country` | `200` | Per-country cap in the combined output |
| `publisher` | `output_file` | `output/subscription.txt` | Combined output path |
| `publisher` | `location_output_limit` | `50` | Cap per `output/locations/subscription-XX.txt` |
| `llm` | `enabled` | `false` | LLM fallback when regex finds no links |

---

## GitHub Actions

[`.github/workflows/update.yml`](.github/workflows/update.yml) — the pipeline:

- **Triggers:** hourly schedule (`0 * * * *`) and manual dispatch (with a
  `skip_publish` input). No push trigger — pushes are handled by `ci.yml`.
- Installs dependencies and a checksum-verified Xray-core, runs the checks and
  the test suite, executes the pipeline, publishes the subscription files, and
  sends an optional Telegram notification with a summary and a fun VPN fact.
- Exit code 3 from `python -m src.main` means "pipeline fine, publish failed":
  the run is marked failed before the notification goes out. See
  [docs/OPERATIONS.md](docs/OPERATIONS.md#exit-codes).

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) — pull requests and
pushes to `main`:

- `lint` (ruff check + format), `typecheck` (`mypy src`), `security`
  (bandit, pip-audit, trufflehog secret scan).
- `test` matrix: Python 3.11/3.12/3.13 on `ubuntu-latest` plus 3.13 on
  `windows-latest`. The suite runs under a coverage gate
  (`--cov-fail-under` in [`pyproject.toml`](pyproject.toml)), so a branch that
  drops tests fails even when every test passes.

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
  links from pages where regex parsing fails. Disabled by default
  (`llm.enabled: false`); the key in `LLM_API_KEY` must match `llm.provider`.
