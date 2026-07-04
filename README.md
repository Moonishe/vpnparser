# VPN Config Parser

Parses VPN configs from public GitHub sources, validates them, and generates a
single subscription link you can add to **Happ** (or any compatible VPN client
that supports base64 subscriptions).

The pipeline runs on a schedule, fetches raw configs and subscription blobs from
GitHub repos you list in `config/sources.json`, parses and validates each server,
deduplicates and sorts the survivors, then publishes a clean subscription file
back to your repo. Add the raw URL of that file as a subscription in Happ and it
stays up to date automatically.

---

## How it works

```
fetch → parse → validate → aggregate → publish
```

1. **Fetch** — pulls files from every enabled source in `config/sources.json`
   (concurrently, with per-source error isolation so one dead repo never breaks
   the run).
2. **Parse** — extracts `vmess://`, `vless://`, `trojan://` and `ss://` links
   into a unified `Config` object, including transport (ws/grpc/h2), TLS/Reality
   params, SNI, flow, etc.
3. **Validate** — checks that each server is actually reachable:
   - **L1** — TCP connect check
   - **L2** — TLS handshake check
   - **L3** *(optional)* — full proxy test through `xray-core`
   - **GeoIP** — enriches each config with its country
4. **Aggregate** — deduplicates by `(protocol, address, port, credential)`,
   sorts by latency (or country), caps per-country and total counts.
5. **Publish** — writes `output/subscription.txt` and commits it to the repo.

---

## Setup

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
pip install -r requirements.txt
```

Then configure your sources and tuning:

- **`config/sources.json`** — list the GitHub repos to fetch configs from. Each
  source has a `type` of either `"subscription"` (a single base64 blob) or
  `"raw"` (a directory of config files). Example:

  ```json
  {
    "sources": [
      {
        "name": "my-free-configs",
        "type": "subscription",
        "owner": "example",
        "repo": "free-vpn",
        "path": "sub",
        "branch": "main",
        "enabled": true
      }
    ]
  }
  ```

- **`config/settings.yaml`** — tuning for validator timeouts, concurrency,
  aggregator limits, publisher mode, and the optional LLM fallback.

---

## Usage

```bash
# Run the pipeline once (writes output/subscription.txt locally)
python -m src.main --run

# Run and publish the result back to the repo (used by CI)
python -m src.main --run --publish

# Verbose logging
python -m src.main -v --run
```

> The `--publish` flag commits to the repo and needs `GITHUB_TOKEN` in the
> environment. Locally, set it to a [personal access token] with `repo` scope.

---

## Auto-update with GitHub Actions

The included workflow `.github/workflows/update.yml` runs the pipeline:

- **every 6 hours** on a schedule,
- on **manual dispatch** (`workflow_dispatch`),
- on **push to `main`** touching `src/`, `config/`, `requirements.txt` or the
  workflow itself (so pipeline changes get validated end-to-end).

The workflow commits `output/subscription.txt` **only when it actually changed**
(`git diff --staged --quiet` guard), and uses the auto-provided `GITHUB_TOKEN`
for both fetching sources (better API rate limits) and pushing the commit.

### Subscribe in Happ

Once the first run has produced `output/subscription.txt`, add this URL as a
subscription in Happ (or any compatible client):

```
https://raw.githubusercontent.com/<your-username>/<repo-name>/main/output/subscription.txt
```

> Replace `<your-username>` and `<repo-name>` with your actual values. The repo
> must be **public** for `raw.githubusercontent.com` to work without auth; if
> it's private, point Happ at a GitHub Gist instead (set `publisher.mode: gist`
> in `config/settings.yaml`).

### Optional secrets

| Secret | Required when | Purpose |
|--------|---------------|---------|
| `GITHUB_TOKEN` | always (auto-provided) | fetching sources + pushing the commit |
| `LLM_API_KEY` | `llm.enabled: true` | LLM fallback for sources regex can't parse |

---

## Supported protocols

| Protocol | Schemes | Notes |
|----------|---------|-------|
| VMess | `vmess://` | base64 JSON, ws/grpc/h2 transports |
| VLESS | `vless://` | Reality + XTLS flow supported |
| Trojan | `trojan://` | TLS, ws/grpc transports |
| Shadowsocks | `ss://` | SIP002 format, method from link |

---

## Validation levels

| Level | What it checks | Needs |
|-------|----------------|-------|
| **L1** | TCP connect to `address:port` | nothing (default) |
| **L2** | TLS handshake + SNI | nothing (default) |
| **L3** | Full proxy round-trip through xray-core | `xray-core` binary (`validator.proxy_test_enabled: true`) |
| **GeoIP** | Country enrichment via ip-api | `validator.geoip_enabled: true` (default) |

L1/L2 run by default. L3 is off by default because it requires the `xray-core`
binary at `validator.xray_binary_path` (`./bin/xray`).

---

## LLM Fallback (optional)

When a source's text contains **zero** links that regex can extract (and the text
is longer than `llm.min_text_length`), the parser can fall back to an LLM to
recover links from unstructured content.

Enable it in `config/settings.yaml`:

```yaml
llm:
  enabled: true
  provider: "groq"                 # "groq" | "openrouter" | "gemini"
  model: "llama-3.1-8b-instant"
  api_key_env: "LLM_API_KEY"       # reads this env var at runtime
  min_text_length: 100
```

Then set the key in your environment:

```bash
export LLM_API_KEY="your-key-here"
```

**Groq** has a free tier and works out of the box. **OpenRouter** and
**Gemini** are also supported — just point `provider` and `model` at the one
you want.

---

## Configuration

Key settings in `config/settings.yaml`:

| Section | Key | Default | What it does |
|---------|-----|---------|--------------|
| `sources` | `cache_ttl_minutes` | `30` | how long fetched source content is cached |
| `sources` | `max_concurrent_fetches` | `10` | concurrency cap for source fetches |
| `validator` | `tcp_timeout_seconds` | `3` | L1 timeout per server |
| `validator` | `tls_timeout_seconds` | `5` | L2 timeout per server |
| `validator` | `proxy_test_enabled` | `false` | enable L3 (needs xray-core) |
| `validator` | `geoip_enabled` | `true` | enrich configs with country |
| `aggregator` | `max_configs_in_output` | `500` | hard cap on output size |
| `aggregator` | `sort_by` | `latency` | `latency` or `country` |
| `aggregator` | `max_per_country` | `50` | cap per country (`0` = unlimited) |
| `publisher` | `mode` | `repo` | `repo` (commit) or `gist` |
| `publisher` | `output_file` | `output/subscription.txt` | where the subscription is written |
| `llm` | `enabled` | `false` | enable LLM fallback for hard sources |

---

## Project structure

```
vpn/
├── .github/
│   └── workflows/
│       └── update.yml          # scheduled auto-update pipeline
├── config/
│   ├── settings.yaml           # validator / aggregator / publisher / LLM tuning
│   └── sources.json            # list of GitHub sources to fetch from
├── output/
│   └── subscription.txt        # generated subscription (committed by CI)
├── src/
│   ├── sources/                # GitHub fetcher + source manager
│   ├── parsers/                # vmess / vless / trojan / ss / subscription parsers
│   ├── validators/             # L1 TCP / L2 TLS / L3 proxy / GeoIP
│   ├── aggregator/             # dedup + sort + per-country limits
│   ├── publisher/              # commit to repo or update gist
│   └── scheduler/              # (reserved for local scheduling)
├── requirements.txt
└── README.md
```

---

## Notes

- The pipeline is **idempotent**: running it twice with the same sources produces
  the same output (modulo ordering of equal-latency configs).
- A failing source is logged and skipped — it never aborts the whole run.
- Output is a **base64 subscription**: the raw file is the base64 of the
  newline-joined config links, which is what Happ expects from a subscription URL.
