"""Scratch TUIC parser probe (no network)."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from src.parsers.base import Config
from src.parsers.tuic import TuicParser
from src.validators.singbox_probe import is_singbox_supported


def main() -> int:
    links = [
        "tuic://11111111-1111-4111-8111-111111111111:pass@example.com:443",
        "tuic://p@example.com:443",
        "tuic://uuid:pass@real-server.com:443",
        "tuic://2f8d3e1c-7b4a-4c9e-8d2f-1a2b3c4d5e6f:secret@1.2.3.4:443?password=secret#name",
    ]

    parsed = 0
    for link in links:
        cfg = TuicParser().parse(link)
        assert cfg is not None, f"FAILED: {link}"
        assert isinstance(cfg, Config)
        parsed += 1
        print(f"{cfg.protocol} {cfg.address}:{cfg.port} remark={cfg.remark!r}")

    print("PARSED", parsed)

    # v5 (uuid:password) is L3-probeable via sing-box; v4 token-only
    # (no ":") parses but has no separable uuid/password for the probe.
    v5 = TuicParser().parse("tuic://uuid:pw@a.com:443?sni=s#T")
    assert v5 is not None and is_singbox_supported(v5)
    v4 = TuicParser().parse("tuic://tokenonly@a.com:443#T")
    assert v4 is not None and not is_singbox_supported(v4)
    print("SINGBOX v5=yes v4=no (expected: v4 parses but is not L3-probed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
