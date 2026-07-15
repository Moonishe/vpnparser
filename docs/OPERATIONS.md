# VPN Config Parser — Operations Runbook

## Daily checks

1. Verify the latest `Update Configs` workflow run is green.
2. Check `output/run-summary.json` for:
   - `configs_count` > 0
   - `xray_alive` reasonable for the list
   - No source banned > 1 run in a row
3. Review Telegram notification (if enabled) for the fun fact and counts.

## When pipeline publishes 0 configs

1. Open `output/run-summary.json` and read `status` and failure reasons.
2. Check `pipeline.log` / GitHub Actions logs for:
   - Proxy pool empty (no free SOCKS5 proxies survived self-check)
   - Xray failures (binary missing, timeout, unsupported configs)
   - All sources dead (fetch failures)
3. If the previous run was healthy, **roll back** to the last known-good commit:
   ```bash
   git log --oneline -10 -- output/
   git revert <bad-commit>
   # or manually restore output/ from the last good commit
   ```
4. If zero output persists > 2 runs, disable automatic publish and investigate manually:
   ```bash
   python -m src.main --run -v
   ```

## Rolling back a bad publish

The `update.yml` workflow creates a single commit per run. To roll back:

```bash
git revert <workflow-commit-sha>
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

- Check the pinned version and checksum in `.github/workflows/update.yml`.
- Verify the asset URL is still valid at `https://github.com/XTLS/Xray-core/releases`.

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
