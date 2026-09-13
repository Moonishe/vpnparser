"""End-to-end pipeline test: black/white/combined/mix/clash/locations.

Runs the REAL pipeline stages (parse → preprocess → quality → aggregate →
whitelist-balance → write) over two real source files with overlapping
configs, varied countries and all four protocols. Only the liveness stage
is stubbed at the single runner seam: a genuine probe would dial public
addresses (SSRF-guarded for anything local by design), and the write stage's
is_alive filtering is exactly what this test verifies end-to-end.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from src.scheduler.runner import PipelineRunner

_UUID = "11111111-1111-4111-8111-111111111111"


def _vless(ip: str, port: int, remark: str) -> str:
    return f"vless://{_UUID}@{ip}:{port}?sni=sni.myvds.net&security=tls#{remark}"


def _trojan(ip: str, port: int, remark: str) -> str:
    return f"trojan://trojanpass@{ip}:{port}?sni=sni.myvds.net#{remark}"


def _ss(ip: str, port: int, remark: str) -> str:
    import base64 as b

    cred = b.b64encode(b"aes-256-gcm:secretpw").decode().rstrip("=")
    return f"ss://{cred}@{ip}:{port}#{remark}"


def _vmess(ip: str, port: int, remark: str) -> str:
    obj = {
        "v": "2",
        "ps": remark,
        "add": ip,
        "port": str(port),
        "id": _UUID,
        "aid": "0",
        "net": "ws",
        "host": "cdn.myvds.net",
        "path": "/ws",
        "tls": "tls",
    }
    return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()


def _real_lines(lines: list[str]) -> list[str]:
    """Drop the display-only watermark vmess (add=0.0.0.0)."""
    out = []
    for ln in lines:
        if not ln.startswith("vmess://"):
            out.append(ln)
            continue
        try:
            payload = base64.b64decode(ln[8:] + "=" * (-len(ln[8:]) % 4)).decode()
            if json.loads(payload).get("add") == "0.0.0.0":
                continue
        except Exception:  # noqa: S110 — a malformed vmess is not a watermark
            pass
        out.append(ln)
    return out


def _decode_sub(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8").strip()
    if "://" in raw:
        return [ln for ln in raw.splitlines() if "://" in ln]
    padded = raw + "=" * (-len(raw) % 4)
    return [ln for ln in base64.b64decode(padded).decode().splitlines() if "://" in ln]


@pytest.fixture
def e2e(tmp_path: Path) -> dict:
    """Two source files, overlapping configs, varied countries; real pipeline."""
    bl_links = [
        _vless("93.184.216.34", 443, "DE-01"),
        _vless("93.184.216.34", 443, "DE-01-DUP"),  # same addr:port -> dedup
        _trojan("8.8.8.8", 8443, "US-01"),
        _ss("8.8.4.4", 8388, "US-02"),
        _vmess("104.16.1.1", 2053, "US-03"),
        _vless("1.1.1.1", 443, "FR-01"),
        # Cross-list dedup: identical addr:port+credential in BOTH lists —
        # the combined pass must collapse them even though each list's own
        # dedup sees only one copy.
        _trojan("141.98.6.1", 8443, "RU-02-DUP"),
    ]
    wl_links = [
        # 8 RU + 4 EU + 1 US (out-of-set): 12 candidates post-dedup makes
        # whitelist_ru_ratio=0.6 bind (ru_target 0.6*11=6 < 8 RU candidates),
        # and the US entry gives the country filter something to reject.
        _vless("185.199.108.153", 443, "RU-01"),
        _vless("185.199.108.153", 443, "RU-01-DUP"),  # in-list dup
        _trojan("141.98.6.1", 8443, "RU-02"),
        _ss("45.9.148.1", 8388, "RU-03"),
        _vless("45.9.148.2", 443, "RU-04"),
        _trojan("45.9.148.3", 8443, "RU-05"),
        _ss("45.9.148.4", 8388, "RU-06"),
        _vless("45.9.148.5", 443, "RU-07"),
        _vless("195.201.1.1", 443, "DE-02"),
        _trojan("195.201.2.2", 443, "NL-01"),
        _vless("195.201.3.3", 443, "FI-01"),
        _trojan("195.201.4.4", 443, "FR-02"),
        _ss("8.8.8.8", 8388, "US-04"),
    ]
    (tmp_path / "src_black.txt").write_text(
        base64.b64encode("\n".join(bl_links).encode()).decode(),
        encoding="utf-8",
    )
    # plain-text twin: exercises the non-base64 subscription path
    (tmp_path / "src_white.txt").write_text(
        "\n".join(wl_links),
        encoding="utf-8",
    )

    settings = f"""
validator:
  allowed_countries_by_list:
    blacklist: []
    whitelist: [RU, DE, FI, NL, FR]
  whitelist_ru_ratio: 0.6
  whitelist_eu_countries: [DE, FI, NL, FR]
  tcp_enabled: false
  tls_enabled: false
  xray_enabled: false
aggregator:
  max_configs_in_output: 100
  max_per_country: 20
  sort_by: country
publisher:
  output_file: {tmp_path / "subscription.txt"}
  mix_output_file: {tmp_path / "subscription-mix.txt"}
  split_output_files:
    blacklist: {tmp_path / "subscription-blacklist.txt"}
    whitelist: {tmp_path / "subscription-whitelist.txt"}
  status_output_file: {tmp_path / "run-summary.json"}
  location_outputs_enabled: true
  location_output_dir: {tmp_path / "locations"}
  location_output_limit: 50
  clash_output_file: {tmp_path / "subscription-clash.yaml"}
  min_publish_configs: 0
quality:
  health_history_enabled: false
llm:
  enabled: false
"""
    (tmp_path / "settings.yaml").write_text(settings, encoding="utf-8")
    (tmp_path / "sources.json").write_text(
        json.dumps({"sources": []}),
        encoding="utf-8",
    )

    runner = PipelineRunner(
        settings_path=str(tmp_path / "settings.yaml"),
        sources_path=str(tmp_path / "sources.json"),
        github_token=None,
    )

    async def fake_fetch() -> list[object]:
        # Fetch paths are SSRF-guarded (localhost/127.0.0.1 refused by
        # design), so the two local files are fed at the runner seam — the
        # exact payload a real fetch would deliver.
        return [
            SimpleNamespace(
                name="e2e-black",
                list_type="blacklist",
                files=[
                    (
                        "src_black.txt",
                        (tmp_path / "src_black.txt").read_text("utf-8"),
                    ),
                ],
                default_country=None,
                error=None,
            ),
            SimpleNamespace(
                name="e2e-white",
                list_type="whitelist",
                files=[
                    (
                        "src_white.txt",
                        (tmp_path / "src_white.txt").read_text("utf-8"),
                    ),
                ],
                default_country=None,
                error=None,
            ),
        ]

    async def fake_validate(configs_by_list: dict) -> dict:
        # Liveness requires real network dials; mark deterministically and
        # record the per-list stats the run summary reads.
        lists_stats: dict = {}
        for lst, configs in configs_by_list.items():
            for idx, cfg in enumerate(configs):
                cfg.is_alive = True
                cfg.latency_ms = 20.0 + idx
            lists_stats[lst] = {
                "tcp_checked": len(configs),
                "tcp_alive": len(configs),
            }
        runner._context.liveness_stats["lists"] = lists_stats
        runner._context.liveness_stats["tcp_enabled"] = True
        runner._liveness_stats = runner._context.liveness_stats
        return configs_by_list

    runner._fetch_sources = fake_fetch  # type: ignore[method-assign]

    runner._validate_liveness_by_list = fake_validate  # type: ignore[method-assign]

    count = _run(runner, str(tmp_path / "subscription.txt"))

    bl = _decode_sub(tmp_path / "subscription-blacklist.txt")
    wl = _decode_sub(tmp_path / "subscription-whitelist.txt")
    combined = _decode_sub(tmp_path / "subscription.txt")
    mix = _decode_sub(tmp_path / "subscription-mix.txt")
    return {
        "count": count,
        "bl": _real_lines(bl),
        "wl": _real_lines(wl),
        "combined": _real_lines(combined),
        "mix": _real_lines(mix),
        "clash": yaml.safe_load(
            (tmp_path / "subscription-clash.yaml").read_text(encoding="utf-8"),
        ),
        "locations": sorted((tmp_path / "locations").glob("subscription-*.txt")),
        "summary": json.loads(
            (tmp_path / "run-summary.json").read_text(encoding="utf-8"),
        ),
        "tmp_path": tmp_path,
    }


def _run(runner: PipelineRunner, output_file: str) -> int:
    import asyncio

    return asyncio.run(runner.run(output_file=output_file, publish=False))


def _remarks(lines: list[str]) -> set[str]:
    """Remarks from the # fragment, or from the vmess JSON ``ps`` field."""
    remarks: set[str] = set()
    for ln in lines:
        if "#" in ln:
            remarks.add(ln.split("#")[-1])
            continue
        if ln.startswith("vmess://"):
            try:
                payload = base64.b64decode(
                    ln[8:] + "=" * (-len(ln[8:]) % 4),
                ).decode()
                ps = json.loads(payload).get("ps")
                if ps:
                    remarks.add(str(ps))
            except Exception:  # noqa: S110 — malformed vmess carries no remark
                pass
    return remarks


class TestE2EBlackWhite:
    def test_combined_and_splits_populated(self, e2e: dict) -> None:
        assert e2e["count"] > 0
        # bl 7 links - 1 in-list dup = 6; wl 13 links - 1 in-list dup
        # (RU-01-DUP shares addr:port+cred with RU-01) - 1 US filtered = 11;
        # combined: 6 + 11 - 1 cross-list collapse (RU-02-DUP vs RU-02) = 16.
        assert len(e2e["bl"]) == 6
        assert len(e2e["wl"]) == 11
        assert len(e2e["combined"]) == 16
        assert len(e2e["mix"]) == 16

    def test_dedup_collapses_duplicates(self, e2e: dict) -> None:
        remarks = _remarks(e2e["combined"])
        assert "DE-01-DUP" not in remarks
        assert "RU-01-DUP" not in remarks
        # The originals survive.
        assert "DE-01" in remarks
        assert "RU-01" in remarks

    def test_whitelist_country_filter(self, e2e: dict) -> None:
        countries = {ln.split("#")[-1][:2] for ln in e2e["wl"] if "#" in ln}
        assert countries <= {"RU", "DE", "FI", "NL", "FR"}

    def test_whitelist_ru_balance(self, e2e: dict) -> None:
        # whitelist_ru_ratio 0.6 binds: 8 RU candidates compete for a
        # ru_target of 0.6 * (7 EU survivors + RU remainder) — the RU share
        # must exceed the EU share, not merely exist.
        ru = sum(1 for ln in e2e["wl"] if ln.split("#")[-1][:2] == "RU")
        eu = len(e2e["wl"]) - ru
        assert ru >= eu, f"RU {ru} vs EU {eu} — the 0.6 quota did not bind"

    def test_blacklist_includes_all_countries(self, e2e: dict) -> None:
        # blacklist has no country filter: US configs survive here only.
        remarks = _remarks(e2e["bl"])
        assert {"US-01", "US-02", "US-03", "FR-01"} <= remarks

    def test_cross_list_dedup_keeps_combined_consistent(self, e2e: dict) -> None:
        # RU-02-DUP rides in BOTH lists with identical addr:port+credential:
        # the combined pass (_dedup_only over all lists) must collapse them
        # even though each list's own dedup sees only one copy.
        # The cross-list pair (identical dedup_key, different remarks) is
        # collapsed to ONE entry in combined — RU-02, the first-seen (whitelist)
        # copy; the blacklist twin RU-02-DUP is dropped by the combined pass.
        assert sum(1 for ln in e2e["combined"] if "RU-02-DUP" in ln) == 0
        assert sum(1 for ln in e2e["combined"] if ln.split("#")[-1] == "RU-02") == 1
        # Both single-list outputs keep their own copy (their dedup sees one
        # copy each); only the combined pass collapses the cross-list pair.
        assert any("RU-02-DUP" in ln for ln in e2e["bl"])
        assert any("RU-02" in ln for ln in e2e["wl"])


class TestE2EClash:
    def test_clash_twins_combined(self, e2e: dict) -> None:
        proxies = e2e["clash"].get("proxies") or []
        assert len(proxies) == len(e2e["combined"])

    def test_clash_protocol_spread(self, e2e: dict) -> None:
        types = {p.get("type") for p in e2e["clash"].get("proxies") or []}
        assert {"vless", "trojan", "ss", "vmess"} <= types

    def test_clash_vmess_ws_transport(self, e2e: dict) -> None:
        vm = next(
            p for p in e2e["clash"].get("proxies") or [] if p.get("type") == "vmess"
        )
        assert vm.get("network") == "ws"
        assert (vm.get("ws-opts") or {}).get("path") == "/ws"


class TestE2ERunSummary:
    def test_summary_status_ok(self, e2e: dict) -> None:
        assert e2e["summary"]["status"] == "ok"

    def test_summary_validation_lists(self, e2e: dict) -> None:
        lists = e2e["summary"]["validation"]["lists"]
        assert {"blacklist", "whitelist"} <= set(lists)

    def test_summary_output_count_matches_file(self, e2e: dict) -> None:
        assert e2e["summary"]["outputs"]["combined"]["count"] == len(
            e2e["combined"],
        )


class TestE2ELocations:
    def test_location_outputs_written(self, e2e: dict) -> None:
        names = {p.name for p in e2e["locations"]}
        assert {
            "subscription-DE.txt",
            "subscription-RU.txt",
            "subscription-US.txt",
        } <= names
