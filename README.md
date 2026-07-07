# VPN Config Parser

Fetches public VPN subscription files from GitHub, parses supported proxy links,
filters and deduplicates them, then writes Happ/v2ray-compatible base64
subscriptions.

The current pipeline produces four files:

- `output/subscription.txt` - combined pool.
- `output/subscription-mix.txt` - strict 75 blacklist + 75 whitelist mix.
- `output/subscription-blacklist.txt` - normal "blacklist" VPN pool.
- `output/subscription-whitelist.txt` - "whitelist" / restricted-network pool.

## Pipeline

```text
fetch -> parse -> garbage filter -> dedup -> country filter -> aggregate -> write -> publish
```

The default mode keeps the country filter fast, then optionally runs a soft TCP
liveness check. GitHub Actions often cannot reach VPN servers directly, so the
validator can build a small free SOCKS5 proxy pool from GitHub-hosted proxy
lists and route TCP checks through it. The liveness stage is fail-open: if the
proxy pool is empty or too few servers validate, the original filtered list is
kept instead of publishing an empty subscription. Each VPN config can be tried
through several different SOCKS5 proxies before it is treated as unreachable.

Configured SOCKS5 proxy pool sources:

- `proxifly/free-proxy-list`
- `ProxyScrape/free-proxy-list`
- `VPSLabCloud/VPSLab-Free-Proxy-List`
- `gfpcom/free-proxy-list` wiki list, used last because it is much larger

## Sources

Sources live in `config/sources.json`. Each source supports:

- `type`: `subscription` for one GitHub file, `raw` for a GitHub directory,
  or `url` for a direct HTTPS text source.
- `list_type`: `blacklist`, `whitelist`, or `mixed`.
- GitHub sources use `owner`, `repo`, `path`, `branch`, `enabled`.
- Direct URL sources use `url`; optional `default_country` is used only when
  country detection from the config itself fails.
- For raw directories: optional `max_depth`, `max_files`, `include_files`, `exclude_files`.

Currently included upstream pools:

- `igareck/vpn-configs-for-russia`
  - Black: `BLACK_VLESS_RUS_mobile.txt`
  - White: `Vless-Reality-White-Lists-Rus-Mobile.txt`, `WHITE-CIDR-RU-checked.txt`,
    `WHITE-CIDR-RU-all.txt`, `WHITE-SNI-RU-all.txt`
- `V2RayRoot/V2RayConfig`
  - Black: `Config/vless.txt`
- `sakha1370/OpenRay`
  - Black: `output/all_valid_proxies.txt`
- `jsxta/whitelist-russia`
  - White subscription: `https://gbr.mydan.online/configs`

Blacklist output keeps only `DE`, `FI`, `NL`, `US`, `GB`, `FR`, `JP`, `CA`.
Whitelist output targets 150 checked configs with an 80% RU / 20% EU split.
The mix output targets 75 checked blacklist configs plus 75 checked whitelist
configs. Subscription titles and Telegram raw GitHub links use
`GITHUB_OWNER/GITHUB_REPO` (or GitHub Actions' `GITHUB_REPOSITORY`) when set.

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
| `validator` | `allowed_countries_by_list` | Per-list country filters |
| `validator` | `whitelist_ru_ratio`, `whitelist_eu_countries` | Whitelist RU/EU split |
| `validator` | `max_configs_to_validate` | `0` means process all parsed configs |
| `validator` | `tcp_enabled`, `tls_enabled` | Network liveness checks |
| `validator` | `proxy_attempts_per_config` | `0` tries all working SOCKS5 proxies for each config |
| `validator` | `proxy_pool` | Optional free SOCKS5 pool for GitHub Actions validation |
| `validator` | `min_alive_to_filter` | Fail-open threshold before liveness filtering is trusted |
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
