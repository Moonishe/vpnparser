# VPN Config Parser — Operations Runbook

## Daily checks

1. Verify the latest `Update Configs` workflow run is green.
2. Check `output/run-summary.json` (top-level keys: `status`, `outputs`, `validation`):
   ```bash
   jq '.status' output/run-summary.json                      # "ok" on a healthy run
   jq '.outputs.combined.count' output/run-summary.json      # configs in subscription.txt
   jq '.outputs | map_values(.count)' output/run-summary.json
   jq '.validation.lists | map_values(.output_after_xray)' output/run-summary.json
   ```
   - `.outputs.combined.count` > 0
   - `.validation.lists.<list>.xray_alive` / `.output_after_xray` reasonable for
     the list; per-source counters are `.validation.lists.<list>.sources.<source>`
     with `checked`/`alive`
   - No source banned > 1 run in a row
3. Review Telegram notification (if enabled) for the fun fact and counts. A
   `skip_publish: true` dispatch sends none on purpose — it publishes nothing,
   so there is no update to announce.

## Exit codes

`python -m src.main` (and therefore the `Run pipeline` step) returns:

| Code | Meaning | Action |
|------|---------|--------|
| `0` | Run finished; publish either succeeded or was not requested | none |
| `1` | Pipeline crashed, or `PipelineRunner` could not be imported | read the traceback in the logs |
| `2` | Bad invocation (no `--run`, or `--publish` without `--run`) | fix the command |
| `3` | Pipeline succeeded but publishing failed — **the subscription in the repo is stale** | see below |
| `130` | Interrupted (Ctrl-C) | none |

### Exit 3 — stale publish

The local `output/` files are fresh, the ones in the repository are not, so
subscribers keep getting the previous run. The workflow fails in the
`Fail on stale publish` step *before* the Telegram step, so no "success"
notification goes out.

1. Confirm the split: `Verify output` shows a healthy local count, while
   `git log -1 --format=%cI -- output/subscription.txt` on `main` is older than
   the run.
2. Find the publisher error in the `Run pipeline` step log — usually one of:
   - expired/insufficient `GITHUB_TOKEN` (401/403),
   - `409` conflict because another run committed in between,
   - rate limit exhausted.
3. Re-running is safe: the pipeline is idempotent, it rewrites the same files
   and republishes them. Re-run the workflow (`Run workflow`) once the cause is
   fixed.
4. If publishing keeps failing, run `python -m src.main --run` (no `--publish`)
   locally to keep artifacts fresh and publish manually from the local `output/`.

## When pipeline publishes 0 configs

1. Open `output/run-summary.json` and read `status` and failure reasons.
2. Check `pipeline.log` / GitHub Actions logs for:
   - Proxy pool empty (no free SOCKS5 proxies survived self-check)
   - Xray failures (binary missing, timeout, unsupported configs)
   - All sources dead (fetch failures)
3. If the previous run was healthy, **roll back** to the last known-good commit —
   see [Rolling back a bad publish](#rolling-back-a-bad-publish); a run spans
   several commits, so reverting one of them is not enough.
4. If zero output persists > 2 runs, disable automatic publish and investigate manually:
   ```bash
   python -m src.main --run -v
   ```

## Rolling back a bad publish

The publisher writes each output file with its own Contents API call, so **one
run produces one commit per file** — 13+ commits in a normal run
(`subscription.txt`, `-mix`, `-blacklist`, `-whitelist`, every
`locations/subscription-XX.txt`, `run-summary.json`, `health-history.json`).
Reverting a single commit therefore restores a single file and leaves the rest
of the bad run in place.

Find the whole range first — all commits of a run share the timestamp in their
`auto-update configs [...]` message:

```bash
git log --oneline -40 -- output/
git log --format='%h %ad %s' --date=iso -40 -- output/
```

Then revert the range (oldest..newest of that run, `--no-commit` keeps it as one
revert commit):

```bash
git revert --no-commit <oldest-bad>^..<newest-bad>
git commit -m "revert bad publish <timestamp>"
git push origin main
```

Alternatively restore the tree state of the last good commit, which cannot miss
a file:

```bash
git checkout <last-good-commit> -- output/
git commit -m "restore output/ from <last-good-commit>"
git push origin main
```

For a faster revert without history pollution (force-push only if safe):

```bash
git reset --hard <last-good-commit>
git push --force-with-lease origin main
```

## Source health

A source may be banned automatically after consecutive bad runs. To inspect:

- `output/health-history.json` — per-config health.
- `output/proxy-health-history.json` — free proxy health.

To unban a source manually, remove its bad history from the cache file or wait for the cooldown (`source_ban_cooldown_hours` in `config/settings.yaml`).

## Xray-core issues

### Binary missing

CI downloads Xray-core on every run. If download fails:

- Check the pinned `XRAY_VERSION` in `.github/workflows/update.yml` and the
  expected digest in `.github/xray.sha256`.
- Verify the asset URL is still valid at `https://github.com/XTLS/Xray-core/releases`.

Locally the binary comes from `XRAY_EXECUTABLE` (see `.env.example`). A relative
value is resolved from the project root, not the working directory, and a bare
name falls back to `PATH`. With `xray_required: true` in `config/settings.yaml`
a missing binary is fail-closed: the liveness stage drops every config and the
run publishes empty files, so check this first when output is empty locally but
fine in CI.

### Suspicious binary

Never run a downloaded Xray binary without verifying it:

```bash
sha256sum /tmp/xray/xray
cat .github/xray.sha256
# compare
```

To update the pinned version, run the helper:

```bash
python scripts/update_xray_checksum.py --version <TAG>
```

(Helper script is planned; until then fetch the checksum manually from the release page.)

## Secrets rotation

Keep backups of the old values in `.env.<something>` (every `.env*` variant
except `.env.example` is gitignored) — never in a file that `git add -A` would
pick up.

Rotate immediately if any secret is suspected leaked:

1. `GITHUB_TOKEN` — GitHub Actions auto-generated; revoke via repo settings.
2. `LLM_API_KEY` — rotate in the LLM provider console and update GitHub secret.
3. `TELEGRAM_BOT_TOKEN` — revoke via @BotFather and update GitHub secret.
4. `TELEGRAM_CHAT_ID` — less sensitive, but verify it is still correct.
5. `VALIDATOR_PROXY` — if a private proxy URL is used, rotate credentials.

## Local debugging

```bash
# Load .env and run with verbose logs
python -m src.main --run -v

# Run without publishing, custom settings
python -m src.main --run --settings config/settings.yaml --sources config/sources.json

# Run tests
python -m pytest -q -p no:cacheprovider
```

## Disaster recovery checklist

- [ ] Stop the scheduled workflow (disable in GitHub Actions UI).
- [ ] Revert the last publish commit.
- [ ] Restore `output/` from the last known-good commit.
- [ ] Rotate any potentially exposed secrets.
- [ ] Run pipeline locally with `-v` to reproduce the issue.
- [ ] Re-enable the workflow only after a successful local run.
