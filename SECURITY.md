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
- Free proxy pool candidates are restricted to public IPv4 addresses.
- Xray execution is time-bounded and the generated config is written to a temporary file.
- LLM output is validated against a strict proxy-link regex before use.
- CI actions are pinned to specific commit SHAs.

## Planned Hardening

- Pin and verify Xray-core release checksums/signatures in CI.
- Run Xray in a sandboxed/network-isolated environment.
- Add a staging publish step with smoke tests before committing to `main`.
- Implement automated secret scanning in pre-commit and CI.
- Scope `GITHUB_TOKEN` to the minimal required permissions.

## Secret Handling

- Never commit `.env` or real credentials to the repository.
- Use GitHub Actions secrets for `GITHUB_TOKEN`, `LLM_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, and `VALIDATOR_PROXY`.
- Rotate secrets periodically and after any suspected leak.
