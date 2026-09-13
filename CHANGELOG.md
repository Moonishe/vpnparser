# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.1] — 2026-09-13

Deployability round: the local line had never been pushed and the publish
repository still ran the 0.1.0 code. This batch removes the known deploy
blockers and the highest-value operational defects found by three audit
passes (details: `outputs/vpnparser-master-plan-2026-09-13.md`).

### Fixed — deployment blockers

- `tests/test_clash.py` normalized to CRLF: an appended LF block failed
  `ruff format --check`, i.e. CI was red before any push.
- `HealthHistory.update()` skips `is_alive=None` verdicts instead of
  recording them as failures — a probed-but-unjudged config no longer
  drifts towards a false 12-hour ban.
- `run-summary.json` reports `sources` again: `_prepare_run_state` had
  started clearing the fetch stats before the summary was written, which
  also silently disabled the Telegram broken-source alert.
- `redact_proxy_url` covers glued lowercase suffixes (`sessionid`,
  `sessiontoken`, `sigv4`, `token2`, `passwd2`) and bare `pass`/`XToken`
  while keeping the AWS presigned coverage and the `monkey`/`keyboard`
  non-redaction.
- `find_all_links` is linear: the userinfo group no longer walks the whole
  tail on `scheme://`-repeated input (240 KB filler: 54 s → milliseconds).
- Per-list override maps (`*_by_list`) match their keys case-insensitively.
- GeoIP sha256 pins compare case-insensitively — an uppercase
  `Get-FileHash` pin used to disable the offline backend forever.
- `xray_min_probe_successes` back to 1 of 2 URLs: 2-of-2 left
  `failures_allowed = 0`, so the first failed probe URL killed the attempt.
- The source permanent-ban threshold is disabled
  (`source_bad_runs_to_disable: 0`) until the whitelist is proven alive
  under CI egress.

### Changed — publication and policy

- The publisher skips files whose content matches the remote (git blob
  SHA): no more ~13 "auto-update" commits per run with identical content.
- Per-file publish floor: subscription slices and location files holding
  fewer than `min_publish_configs` configs are withheld, and every
  withholding is reported in `run-summary.json` under
  `publish_floor_applied`.
- The stability gate exempts first-ever passes
  (`stability_exempt_first_pass`, on by default): a new candidate can enter
  the subscription without surviving a second full run first.
- `_degraded_reasons` also flags alive rates below 2% (at ≥100 checked),
  not only exactly-zero outcomes.
- The proxy-pool search merges rounds monotonically (a wider later round no
  longer erases a better earlier result) and its recovery self-check probes
  the configured `probe_host`/`probe_port`/extra targets.
- The health history save re-reads and merges the on-disk file under a
  shared cross-process lock — a full run and the hourly fast-track no
  longer lose each other's records.
- Proxy health record keys are the dial target (`scheme://host:port`);
  old credential-bearing keys migrate and merge.
- `wireguard://` removed from the link-extraction schemes (no parser and no
  end-to-end support; extracted links were silently discarded afterwards).

## [0.2.0] — 2026-09-02

Two audit and remediation campaigns (~100 fixes) after which the pipeline is
production-hardened: publication can no longer silently fail or silently
succeed, probe verdicts are trustworthy, and the codebase is split into
cohesive modules.

### Fixed — publication correctness

- **CI reported every pipeline failure green**: `update.yml` captured the
  exit status of a variable assignment, not the interpreter — exit 1 (crash)
  and exit 3 (stale publish) were invisible, "Fail on stale publish" was dead
  code, and Telegram announced updates that never landed.
- **Publication failed on every run**: the 25 MB `health-history.json`
  exceeded the Contents API body limit in a single PUT, so the whole batch
  exited 3. It is now written locally (Telegram report + workflow cache read
  it) but no longer published.
- Empty whitelist slices from a non-empty input published a watermark over a
  working published file (the empty-slice publish floor keyed on file size,
  which a watermark defeats).
- Fast-track `published` output no longer advertises a publish that only
  covered metadata.

### Fixed — verdict trust

- **Proxy-pool refill was a no-op** that also burned the once-per-run
  refetch flag: the getter served the cached dying pool, then the real
  recovery path was disarmed. The cache is invalidated first, restored on
  failure, and the flag only set on success.
- **Proxy ranking dropped any proxy that ever failed once** without a
  recorded latency (`inf > max_latency_ms`) until 24 h retention forgot it.
- Health-history sanitizer covers the cumulative sample fields — a single
  hand-edited value crashed every subsequent run (liveness stage) before
  `save()` could repair the file.
- One verdict per config per run in the TCP/TLS-only path too (dedup against
  `_health_update_seen`): a server riding in two lists had its ban threshold
  halved.
- `xray_stage_budget_minutes` is now ONE absolute deadline shared by the
  fresh/retry/stale passes and the sing-box pass (which previously had **no
  budget at all**) instead of three per-call budgets (up to 3x).
- Per-config probe ceiling (`xray_per_config_timeout_seconds`): one slow URL
  chain can no longer pin a stage semaphore slot for minutes.
- TCP/TLS verdicts are recorded even when the Xray branch is skipped
  (binary missing, no candidates) — previously the whole sweep's evidence
  was discarded.

### Fixed — parsers & output

- Comma/semicolon-joined links no longer glue into one unparseable match
  (`alpn=h3,h2` still works).
- Percent-encoded base64 padding (`%3D`) no longer kills vmess links.
- One non-UTF-8 byte no longer discards an entire subscription.
- Dead configs can no longer evict their live twin in dedup, and the Clash
  YAML twin skips them like the base64 writer does.
- hysteria2 `obfs`/`obfs-password` reach the Clash writer and the sing-box
  probe (salamander servers were probed and published without obfuscation).
- `aggregator.max_configs_in_output: 0` means unlimited — one semantic
  across the codebase (it used to empty every output).

### Security

- **Raw GitHub downloads use a dedicated auth-free client**: routing them
  through the API client would have leaked the bearer token to
  raw.githubusercontent.com (httpx merges client headers).
- L3 probes (Xray/sing-box) pin the connect target to the validated address
  (DNS rebinding), matching the TCP/TLS stages; the identity-probe answer is
  rejected when it reports a private IP; obfuscated loopback literals
  (`2130706433`, `0x7f000001`, `127.1`) are judged through canonicalization.
- Runtime SSRF check for the LLM `api_base` (the docstring promised it; it
  did not exist) and for the GeoIP endpoint.
- sing-box forwards SOCKS credentials and accepts http proxies (parity with
  Xray) — an authenticated pool entry made every QUIC config look dead.
- Proxy-health history is keyed by credential-free URL (secret-at-rest fix).
- `redact_proxy_url` no longer rewrites jsDelivr-style `@version` paths, and
  covers `license_key`/`X-Amz-*`/`access_token` query secrets.
- TLS context cache is keyed on a bounded ALPN set: untrusted `alpn=` values
  minted unlimited cached SSLContexts (and ~15 ms of blocking work each).
- Stale probe temp dirs (carrying probe credentials) are swept at stage
  start, age-guarded so a concurrent pipeline's live probe is not deleted.

### Performance

- One `httpx.AsyncClient` per url-list batch / per GeoIP batch / per LLM
  parser / long-lived API+raw clients (previously per URL, per IP, per
  attempt, per file — ~0.2 s of blocked loop each).
- One absolute per-list deadline (see above), in-memory proxy-latency
  baselines instead of a per-list disk reload, incremental body decoding
  (peak memory −3x), `MAX_INFLIGHT_DOWNLOADS` derived from the byte budget
  (~1.5 GB worst case → ~384 MB), single `detect_country` pass over the
  corpus, `id()`-based liveness set ops, gather-vs-watcher races replacing
  O(n²) `asyncio.wait` loops in all four probe stages, cached TLS context.

### Changed

- `telegram.py` (1383 lines) split into `html_limits.py` + `report.py`;
  `liveness.py` gained the `liveness_pool.py` mixin; ~450 lines of dead
  compatibility shims and a second, diverging write pipeline removed.
- Wheel installs correctly (`packages` covers `src` + entry point
  `vpnparser`); `VPNPARSER_PROJECT_ROOT` pins the containment base for the
  installed script; `resolve_safe_output_path` root lookup is cached.
- 404 grace and 403/429 rate-limit handling apply to the 5xx-retry answer
  too; the rate-limit wait carries jitter; 502/503/504 are retried once.
- CI gained a non-editable wheel build + smoke-test job; the CI badge points
  at `ci.yml` (the publish workflow got its own badge); Dependabot covers
  the SHA-pinned Actions; `pytest-timeout` bounds every test.

## [0.1.0] — initial pipeline

Fetch, parse, validate (TCP/TLS/Xray L3 + sing-box QUIC), and publish VPN
proxy subscriptions via the GitHub Contents API, with Telegram reporting.

[0.2.0]: https://github.com/Moonishe/vpnparser/releases/tag/v0.2.0
[0.1.0]: https://github.com/Moonishe/vpnparser/releases/tag/v0.1.0
