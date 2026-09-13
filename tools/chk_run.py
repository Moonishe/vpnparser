"""End-to-end PipelineRunner proof with mocked source fetch (network mocked)."""

from __future__ import annotations

import asyncio
import base64
import json
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from src.scheduler.runner import PipelineRunner
from src.sources.manager import SourceManager, SourceResult

TMP = Path(tempfile.mkdtemp(prefix="chk_run_"))


def _vmess_link() -> str:
    payload = json.dumps(
        {
            "v": "2",
            "ps": "DE-01",
            "add": "de.server.net",
            "port": "443",
            "id": "11111111-1111-4111-8111-111111111111",
            "aid": "0",
            "net": "tcp",
            "type": "none",
            "host": "",
            "path": "",
            "tls": "tls",
        },
        separators=(",", ":"),
    )
    return "vmess://" + base64.b64encode(payload.encode()).decode()


LINKS = [
    _vmess_link(),
    "vless://11111111-1111-4111-8111-111111111111@de.server.net:443#DE-02",
    "ss://YWVzLTI1Ni1nY206cGFzcw@fi.server.net:8388#FI-01",
]
CONTENT = "\n".join(LINKS) + "\n"


def _fake_fetch_all(self):
    async def _impl():
        return [
            SourceResult(
                source_name="mocked",
                files=[("proxies.txt", CONTENT)],
                list_type="mixed",
                default_country=None,
            )
        ]

    return _impl()


SourceManager.fetch_all = _fake_fetch_all


def main() -> int:
    settings = TMP / "settings.yaml"
    sources = TMP / "sources.json"
    settings.write_text(
        """
sources:
  max_concurrent_fetches: 2
validator:
  allowed_countries: []
  tcp_enabled: false
  tls_enabled: false
  xray_enabled: false
  max_configs_to_validate: 0
quality:
  health_history_enabled: false
  min_consecutive_passes: 1
  drop_slow_configs: false
aggregator:
  max_configs_in_output: 500
publisher:
  output_file: "%s"
  mix_output_file: "%s"
  clash_output_file: "%s"
  location_outputs_enabled: false
  status_output_file: "%s"
  split_output_files: {}
  min_publish_configs: 0
"""
        % (
            str(TMP / "subscription.txt").replace("\\", "/"),
            str(TMP / "subscription-mix.txt").replace("\\", "/"),
            str(TMP / "subscription-clash.yaml").replace("\\", "/"),
            str(TMP / "run-summary.json").replace("\\", "/"),
        ),
        encoding="utf-8",
    )
    sources.write_text(json.dumps({"sources": []}), encoding="utf-8")

    runner = PipelineRunner(
        settings_path=str(settings),
        sources_path=str(sources),
    )

    # All validators are off in this fixture settings: fail-closed liveness
    # would mark everything dead (is_alive=False) and the proof would always
    # FAIL. Mock the liveness gate to alive so the script proves the
    # fetch->parse->aggregate->write->publish plumbing, not the probes.
    async def _fake_validate_by_list(configs_by_list, **_kwargs):
        for configs in configs_by_list.values():
            for cfg in configs:
                cfg.is_alive = True
        return dict(configs_by_list)

    runner._liveness.validate_by_list = _fake_validate_by_list  # type: ignore[method-assign]

    out = str(TMP / "subscription.txt")
    count = asyncio.run(runner.run(output_file=out, publish=False))

    produced = count
    sub_file = Path(out)
    written = sub_file.exists()
    decoded_links = 0
    decode_ok = False
    if written:
        raw = sub_file.read_text(encoding="utf-8").strip()
        try:
            text = base64.b64decode(raw).decode("utf-8")
            decoded_links = sum(1 for ln in text.splitlines() if "://" in ln)
            decode_ok = decoded_links >= 3
        except Exception:
            decode_ok = False

    print("=== PIPELINE RUNNER E2E ===")
    print("produced_count:", produced)
    print("subscription_written:", written)
    print("decoded_link_count:", decoded_links)
    print("decode_ok(>=3):", decode_ok)
    print("verdict:", "PASS" if produced >= 3 and written and decode_ok else "FAIL")
    return 0 if produced >= 3 and written and decode_ok else 1


if __name__ == "__main__":
    sys.exit(main())
