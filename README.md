# VPN Config Parser

Fetches public VPN subscription files from GitHub, parses supported proxy links,
filters and deduplicates them, then writes Happ/v2ray-compatible base64
subscriptions.

The current pipeline produces three files:

- `output/subscription.txt` - combined pool.
- `output/subscription-blacklist.txt` - normal "blacklist" VPN pool.
- `output/subscription-whitelist.txt` - "whitelist" / restricted-network pool.

## Pipeline

```text
fetch -> parse -> garbage filter -> dedup -> country filter -> aggregate -> write -> publish
```

The default mode is intentionally fast: it does not run TCP/TLS/GeoIP network
checks. It detects countries from remarks, hostnames, SNI, and source metadata,
then caps the output per country. TCP/TLS validators still exist in `src/validators`
and can be wired in later for a slower live-check mode.

## Sources

Sources live in `config/sources.json`. Each source supports:

- `type`: `subscription` for one file or `raw` for a directory.
- `list_type`: `blacklist`, `whitelist`, or `mixed`.
- `owner`, `repo`, `path`, `branch`, `enabled`.
- For raw directories: optional `max_depth`, `max_files`, `include_files`, `exclude_files`.

Currently included upstream pools:

- `igareck/vpn-configs-for-russia`
  - Black: `BLACK_VLESS_RUS_mobile.txt`, `BLACK_VLESS_RUS.txt`, `BLACK_SS+All_RUS.txt`
  - White: `Vless-Reality-White-Lists-Rus-Mobile.txt`, `WHITE-CIDR-RU-checked.txt`, `WHITE-CIDR-RU-all.txt`
- `AvenCores/goida-vpn-configs`
  - Selected mirrors: `githubmirror/1.txt`, `6.txt`, `22.txt`, `24.txt`, `25.txt`
  - White/SNI-CIDR: `githubmirror/26.txt`
- `hiztin/VLESS-PO-GRIBI`
  - `deploy/sub.txt`
- `VAL41K/bypass-rkn-blocks`
  - Black: `configs/obhod_BL`
  - White: `configs/obhod_WL`

`AvenCores/goida-vpn-configs` is intentionally not fetched from repo root and
does not include every mirror file. Some mirrors are huge or duplicate other
configured sources.

## Supported Protocols

| Protocol | Schemes |
| --- | --- |
| VMess | `vmess://` |
| VLESS | `vless://` |
| Trojan | `trojan://` |
| Shadowsocks | `ss://` |
| Hysteria2 | `hysteria2://`, `hy2://` |
| TUIC | `tuic://` |
| ShadowTLS | `shadowtls://` |
| AnyTLS | `anytls://` |

## Setup

```bash
pip install -r requirements.txt
```

Local `.env` files are loaded automatically when `python-dotenv` is installed.
Useful variables:

```text
GITHUB_TOKEN=
GITHUB_OWNER=
GITHUB_REPO=
GITHUB_BRANCH=main
LLM_API_KEY=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
VALIDATOR_PROXY=
```

`GITHUB_TOKEN` is useful even for fetch-only runs because unauthenticated GitHub
API calls hit rate limits quickly.

## Usage

```bash
python -m src.main --run
python -m src.main --run --publish
python -m src.main --run -v
```

Run tests:

```bash
python -m pytest -q -p no:cacheprovider
```

## Configuration

Important settings in `config/settings.yaml`:

| Section | Key | Meaning |
| --- | --- | --- |
| `sources` | `max_concurrent_fetches` | Concurrent source fetch limit |
| `validator` | `allowed_countries` | Empty list keeps all countries |
| `validator` | `max_configs_to_validate` | `0` means process all parsed configs |
| `validator` | `tcp_enabled`, `tls_enabled` | Reserved for slower live validation |
| `aggregator` | `max_configs_in_output` | Hard cap per generated file |
| `aggregator` | `max_per_country` | Per-country cap |
| `publisher` | `output_file` | Combined output path |
| `publisher` | `split_output_files` | Blacklist/whitelist output paths |
| `llm` | `enabled` | Optional LLM fallback when regex finds no links |

## GitHub Actions

`.github/workflows/update.yml` runs hourly, on manual dispatch, and on pushes
touching the pipeline. It installs dependencies, runs tests, executes the
pipeline, publishes generated subscription files, and sends an optional Telegram
notification.

## Notes

- Output files are base64-encoded subscriptions containing newline-separated
  raw proxy links.
- Each output starts with a harmless VMess watermark entry so the subscription
  is easy to identify in clients.
- Fetch failures are isolated per source; one dead upstream does not fail the
  whole run.
