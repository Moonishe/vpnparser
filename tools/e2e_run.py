"""E2E test run: real pipeline stages (fetch→parse→quality→aggregate→write),
liveness stubbed at the single runner seam (network dials cannot reach
127.0.0.1 through the SSRF guard by design). Exercises: base64+plain
subscriptions from two "sources", dedup across lists, country filter,
whitelist RU/EU balance, mix, clash yaml, per-location outputs, run-summary.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, ".")

from src.scheduler.runner import PipelineRunner

UUID = "11111111-1111-4111-8111-111111111111"


def vless(ip: str, port: int, remark: str, sni: str | None = "sni.myvds.net") -> str:
    q = f"?sni={sni}" if sni else ""
    return f"vless://{UUID}@{ip}:{port}{q}#{remark}"


def trojan(ip: str, port: int, remark: str) -> str:
    return f"trojan://trojanpass@{ip}:{port}?sni=sni.myvds.net#{remark}"


def ss(ip: str, port: int, remark: str) -> str:
    import base64 as b

    cred = b.b64encode(b"aes-256-gcm:secretpw").decode().rstrip("=")
    return f"ss://{cred}@{ip}:{port}#{remark}"


def vmess(ip: str, port: int, remark: str) -> str:
    obj = {
        "v": "2",
        "ps": remark,
        "add": ip,
        "port": str(port),
        "id": UUID,
        "aid": "0",
        "net": "ws",
        "host": "cdn.myvds.net",
        "path": "/ws",
        "tls": "tls",
    }
    return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="vpnparser-e2e-"))
    print(f"== E2E run in {tmp}")

    # --- fixtures: two source files, overlapping (dedup) + varied countries.
    # Public-looking addresses (real dials would fail; liveness is stubbed).
    bl_links = [
        vless("93.184.216.34", 443, "DE-01"),
        vless("93.184.216.34", 443, "DE-01-DUP"),  # same addr:port -> dedup
        trojan("198.51.100.7", 8443, "US-01"),
        ss("203.0.113.10", 8388, "US-02"),
        vmess("192.0.2.55", 2053, "US-03"),
        vless("203.0.113.99", 443, "FR-01"),
        # Cross-list dedup: same dedup_key as whitelist RU-02, different remark.
        trojan("141.98.6.1", 8443, "RU-02-DUP"),
    ]
    wl_links = [
        # 8 RU + 4 EU + 1 US (out-of-set): 12 candidates post-dedup makes
        # whitelist_ru_ratio=0.6 bind, and the US entry gives the country
        # filter something to reject.
        vless("185.199.108.153", 443, "RU-01"),
        vless("185.199.108.153", 443, "RU-01-DUP"),  # in-list dup
        trojan("141.98.6.1", 8443, "RU-02"),
        ss("45.9.148.1", 8388, "RU-03"),
        vless("45.9.148.2", 443, "RU-04"),
        trojan("45.9.148.3", 8443, "RU-05"),
        ss("45.9.148.4", 8388, "RU-06"),
        vless("45.9.148.5", 443, "RU-07"),
        vless("195.201.1.1", 443, "DE-02"),
        trojan("195.201.2.2", 443, "NL-01"),
        vless("195.201.3.3", 443, "FI-01"),
        trojan("195.201.4.4", 443, "FR-02"),
        ss("198.51.100.77", 8388, "US-04"),
    ]
    bl_text = base64.b64encode("\n".join(bl_links).encode()).decode()
    wl_text = "\n".join(wl_links)  # plain-text twin: exercises non-b64 path

    (tmp / "src_black.txt").write_text(bl_text, encoding="utf-8")
    (tmp / "src_white.txt").write_text(wl_text, encoding="utf-8")

    sources = {
        "sources": [
            {
                "name": "e2e-black",
                "type": "url",
                "url": f"file://{tmp / 'src_black.txt'}",
                "list_type": "blacklist",
                "enabled": True,
            },
            {
                "name": "e2e-white",
                "type": "url",
                "url": f"file://{tmp / 'src_white.txt'}",
                "list_type": "whitelist",
                "enabled": True,
            },
        ],
    }
    import json as j

    (tmp / "sources.json").write_text(j.dumps(sources), encoding="utf-8")

    combined = tmp / "subscription.txt"
    settings = f"""
sources:
  max_concurrent_fetches: 4
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
  output_file: {combined}
  mix_output_file: {tmp / "subscription-mix.txt"}
  split_output_files:
    blacklist: {tmp / "subscription-blacklist.txt"}
    whitelist: {tmp / "subscription-whitelist.txt"}
  status_output_file: {tmp / "run-summary.json"}
  location_outputs_enabled: true
  location_output_dir: {tmp / "locations"}
  location_output_limit: 50
  clash_output_file: {tmp / "subscription-clash.yaml"}
  min_publish_configs: 0
quality:
  health_history_enabled: false
llm:
  enabled: false
"""
    (tmp / "settings.yaml").write_text(settings, encoding="utf-8")

    runner = PipelineRunner(
        settings_path=str(tmp / "settings.yaml"),
        sources_path=str(tmp / "sources.json"),
        github_token=None,
    )

    # Feed source files directly (all network fetch paths are guarded against
    # private addresses by design — localhost included). The files are the
    # same payload a real fetch would deliver.
    async def fake_fetch() -> list[object]:
        from types import SimpleNamespace

        return [
            SimpleNamespace(
                name="e2e-black",
                list_type="blacklist",
                files=[("src_black.txt", (tmp / "src_black.txt").read_text("utf-8"))],
                default_country=None,
                error=None,
            ),
            SimpleNamespace(
                name="e2e-white",
                list_type="whitelist",
                files=[("src_white.txt", (tmp / "src_white.txt").read_text("utf-8"))],
                default_country=None,
                error=None,
            ),
        ]

    runner._fetch_sources = fake_fetch  # type: ignore[method-assign]

    # Single seam: liveness requires real network dials (SSRF guard refuses
    # 127.0.0.1 both for source fetch and config probes — by design). Mark
    # configs alive deterministically; everything else runs for real.
    async def fake_validate(configs_by_list):
        # NOTE: _apply_quality_filters is sync here (delegates to QualityFilter);
        # data arrives as the dict of lists.
        lists_stats = {}
        for lst, configs in configs_by_list.items():
            for idx, cfg in enumerate(configs):
                cfg.is_alive = True
                cfg.latency_ms = 20.0 + idx
            lists_stats[lst] = {"tcp_checked": len(configs), "tcp_alive": len(configs)}
        runner._context.liveness_stats["lists"] = lists_stats
        runner._context.liveness_stats["tcp_enabled"] = True
        runner._liveness_stats = runner._context.liveness_stats
        return configs_by_list

    runner._validate_liveness_by_list = fake_validate  # type: ignore[method-assign]

    asyncio.run(runner.run(output_file=str(combined), publish=False))

    ok = True

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        mark = "PASS" if cond else "FAIL"
        if not cond:
            ok = False
        print(f"  [{mark}] {name}{(' — ' + detail) if detail else ''}")

    print("== outputs")

    def decode_sub(p: Path) -> list[str]:
        raw = p.read_text(encoding="utf-8").strip()
        if "://" in raw:
            return [ln for ln in raw.splitlines() if "://" in ln]
        return [
            ln
            for ln in base64.b64decode(raw + "=" * (-len(raw) % 4))
            .decode()
            .splitlines()
            if "://" in ln
        ]

    bl_out = decode_sub(tmp / "subscription-blacklist.txt")
    wl_out = decode_sub(tmp / "subscription-whitelist.txt")
    combined_out = decode_sub(combined)
    mix_out = decode_sub(tmp / "subscription-mix.txt")

    def real(lines: list[str]) -> list[str]:
        """Drop the display-only watermark vmess (add=0.0.0.0)."""
        import base64 as _b64
        import json as _json

        out = []
        for ln in lines:
            if not ln.startswith("vmess://"):
                out.append(ln)
                continue
            try:
                payload = _b64.b64decode(
                    ln[8:] + "=" * (-len(ln[8:]) % 4),
                ).decode()
                if _json.loads(payload).get("add") == "0.0.0.0":
                    continue
            except Exception:  # noqa: S110 — a malformed vmess is not a watermark
                pass
            out.append(ln)
        return out

    bl_out = real(bl_out)
    wl_out = real(wl_out)
    combined_out = real(combined_out)
    mix_out = real(mix_out)

    check("combined populated", len(combined_out) == 16, f"{len(combined_out)} configs")
    check("blacklist == 6", len(bl_out) == 6)
    check("whitelist == 11", len(wl_out) == 11)
    check("mix == 16", len(mix_out) == 16)
    # Cross-list dedup: the pair collapses to one entry in combined.
    check(
        "cross-list dedup collapses",
        sum(1 for ln in combined_out if "RU-02-DUP" in ln) == 0
        and any("RU-02-DUP" in ln for ln in bl_out),
    )
    check(
        "blacklist populated",
        len(bl_out) > 0,
        f"{len(bl_out)}: {sorted({ln.split('#')[-1] for ln in bl_out})}",
    )
    check(
        "whitelist populated",
        len(wl_out) > 0,
        f"{len(wl_out)}: {sorted({ln.split('#')[-1] for ln in wl_out})}",
    )
    check("mix populated", len(mix_out) > 0, f"{len(mix_out)} (50/50 halves)")

    # Dedup: DE-01 dup and cross-list RU-01 dup must collapse.
    dedup_count = sum(
        1 for ln in combined_out if "DE-01-DUP" in ln or "RU-01-DUP" in ln
    )
    check("duplicates collapsed", dedup_count == 0, f"{dedup_count} dup remarks left")

    # Country filter on whitelist: only RU/DE/FI/NL/FR survive.
    wl_countries = {ln.split("#")[-1][:2] for ln in wl_out}
    check(
        "whitelist country-filtered",
        wl_countries <= {"RU", "DE", "FI", "NL", "FR"},
        f"countries: {sorted(wl_countries)}",
    )

    # Whitelist balance: RU share ~60%.
    ru = sum(1 for ln in wl_out if ln.split("#")[-1][:2] == "RU")
    eu = len(wl_out) - ru
    check(
        "whitelist RU-majority (quota binds)",
        ru >= eu,
        f"RU {ru} vs EU {eu} (ratio target 0.6)",
    )

    # Clash yaml twin.
    clash = tmp / "subscription-clash.yaml"
    import yaml

    doc = yaml.safe_load(clash.read_text(encoding="utf-8"))
    proxies = doc.get("proxies") or []
    check(
        "clash twins combined",
        len(proxies) == len(combined_out),
        f"{len(proxies)} proxies",
    )
    types = {p.get("type") for p in proxies}
    check(
        "clash protocol spread",
        {"vless", "trojan", "ss", "vmess"} <= types,
        f"types: {sorted(types)}",
    )
    vm = next(p for p in proxies if p.get("type") == "vmess")
    check(
        "vmess ws-opts present",
        vm.get("network") == "ws" and "ws-opts" in vm,
        f"path={vm.get('ws-opts', {}).get('path')}",
    )

    # Locations.
    locations = sorted((tmp / "locations").glob("subscription-*.txt"))
    check("location outputs", len(locations) > 0, f"{[p.name for p in locations]}")

    # Run summary sanity.
    summary = json.loads((tmp / "run-summary.json").read_text(encoding="utf-8"))
    check("summary status ok", summary.get("status") == "ok", summary.get("status"))
    check(
        "summary validation recorded",
        summary.get("validation", {}).get("lists", {}).keys()
        >= {"blacklist", "whitelist"},
        str(list(summary.get("validation", {}).get("lists", {}).keys())),
    )
    check(
        "summary output counts match files",
        summary.get("outputs", {}).get("combined", {}).get("count")
        == len(combined_out),
        str(summary.get("outputs", {}).get("combined", {}).get("count")),
    )

    print("== fixtures kept for inspection:", tmp)
    print("== RESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
