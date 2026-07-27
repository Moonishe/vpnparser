# Security Policy

## Supported Versions

This project is under active development. Only the latest commit on the `main` branch is supported with security fixes.

| Version / Branch | Supported |
| ---------------- | --------- |
| `main` (latest)    | Yes       |
| older commits      | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do not open a public issue.**
2. Send an email to the repository owner with a detailed description.
3. Allow reasonable time for investigation and remediation before disclosure.

## Known Risk Areas

This project processes untrusted network data and executes third-party binaries. The following components are high-risk and reviewed regularly:

- **External sources**: `config/sources.json` downloads proxy lists from third-party URLs without content pinning.
- **Network validators**: TCP/TLS checks connect to arbitrary addresses parsed from subscription links.
- **Free SOCKS5 proxy pool**: validation traffic is routed through untrusted third-party proxies.
- **Xray-core subprocess**: a downloaded external binary is executed with a generated JSON config.
- **LLM fallback**: source text may be sent to external LLM providers when regex parsing fails.
- **GitHub publisher**: the CI workflow has `contents: write` permission to publish generated files.
- **Secrets**: GitHub/Telegram/LLM tokens are read from environment variables.

## Mitigations in Place

- SSRF protection rejects private, loopback, link-local, and reserved IP addresses in validators.
  Hostnames are resolved first (`check_hostnames=True` in the TCP, TLS, and Xray validators),
  so a config pointing at `localhost.example.com` is rejected too.
- Source fetches of third-party URLs (`url-list` indexes and their targets) are restricted to
  an `http`/`https` allowlist, re-checked against the SSRF guard on **every redirect hop**
  (`follow_redirects=False`, bounded hop count), and truncated past `MAX_DOWNLOAD_BYTES`.
- Free proxy pool candidates are restricted to public IPv4 addresses.
- Xray execution is time-bounded and the generated config is written to a temporary file.
  Xray L3 probes verify the TLS certificate of the probe URL by default.
- GeoIP enrichment shares one global rate limiter and a per-run lookup cap, so an untrusted
  source cannot turn a run into thousands of third-party API calls.
- LLM output is validated against a strict proxy-link regex before use.
- CI actions are pinned to specific commit SHAs, and the Xray-core release is pinned by tag
  and verified against `.github/xray.sha256` before it is executed.
- Secret scanning runs in both places: `detect-private-key` in pre-commit and a trufflehog
  scan in `ci.yml` (diff-scan on pull requests, full checkout otherwise).

## Planned Hardening

- Run Xray in a sandboxed/network-isolated environment.
- Add a staging publish step with smoke tests before committing to `main`.
- Scope `GITHUB_TOKEN` to the minimal required permissions.

## Secret Handling

- Never commit `.env` or real credentials to the repository. `.gitignore` covers every
  `.env*` variant (`.env.local`, a `.env.bak` left over from a rotation, …) except the
  `.env.example` template.
- Use GitHub Actions secrets for `GITHUB_TOKEN`, `LLM_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, and `VALIDATOR_PROXY`.
- Rotate secrets periodically and after any suspected leak.
