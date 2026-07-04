"""Country detection from config remark/server name.

Many public VPN configs include country indicators in their display names:
- Flag emojis: 🇩🇪 🇫🇮 🇳🇱 🇺🇸
- Country codes: DE, FI, NL, US, DE-01, USA-02
- Country names: Germany, Finland, Netherlands, USA

This module extracts a 2-letter ISO country code from the remark string
**without any network calls** — instant for hundreds of thousands of configs.
"""

from __future__ import annotations

import re

# --- emoji flag → ISO code map ---
# Flag emojis are built from regional indicator pairs. We map the common ones.
_EMOJI_TO_CODE: dict[str, str] = {
    "🇩🇪": "DE",  # Germany
    "🇫🇮": "FI",  # Finland
    "🇳🇱": "NL",  # Netherlands
    "🇺🇸": "US",  # USA
    "🇬🇧": "GB",  # UK
    "🇫🇷": "FR",  # France
    "🇯🇵": "JP",  # Japan
    "🇸🇬": "SG",  # Singapore
    "🇨🇦": "CA",  # Canada
    "🇦🇺": "AU",  # Australia
    "🇰🇷": "KR",  # Korea
    "🇭🇰": "HK",  # Hong Kong
    "🇹🇼": "TW",  # Taiwan
    "🇮🇳": "IN",  # India
    "🇷🇺": "RU",  # Russia
    "🇹🇷": "TR",  # Turkey
    "🇮🇷": "IR",  # Iran
    "🇵🇱": "PL",  # Poland
    "🇸🇪": "SE",  # Sweden
    "🇨🇭": "CH",  # Switzerland
    "🇦🇹": "AT",  # Austria
    "🇧🇪": "BE",  # Belgium
    "🇪🇸": "ES",  # Spain
    "🇮🇹": "IT",  # Italy
    "🇨🇿": "CZ",  # Czech Republic
    "🇺🇦": "UA",  # Ukraine
    "🇧🇷": "BR",  # Brazil
    "🇲🇽": "MX",  # Mexico
    "🇮🇩": "ID",  # Indonesia
    "🇹🇭": "TH",  # Thailand
    "🇻🇳": "VN",  # Vietnam
    "🇵🇭": "PH",  # Philippines
    "🇲🇾": "MY",  # Malaysia
    "🇦🇪": "AE",  # UAE
    "🇿🇦": "ZA",  # South Africa
    "🇦🇷": "AR",  # Argentina
}

# --- country name → ISO code ---
_NAME_TO_CODE: dict[str, str] = {
    "germany": "DE",
    "deutschland": "DE",
    "finland": "FI",
    "suomi": "FI",
    "netherlands": "NL",
    "holland": "NL",
    "nederland": "NL",
    "usa": "US",
    "united states": "US",
    "america": "US",
    "us": "US",
    "uk": "GB",
    "united kingdom": "GB",
    "england": "GB",
    "france": "FR",
    "japan": "JP",
    "singapore": "SG",
    "canada": "CA",
    "australia": "AU",
    "korea": "KR",
    "south korea": "KR",
    "hong kong": "HK",
    "hongkong": "HK",
    "taiwan": "TW",
    "india": "IN",
    "russia": "RU",
    "россия": "RU",
    "turkey": "TR",
    "türkiye": "TR",
    "iran": "IR",
    "poland": "PL",
    "sweden": "SE",
    "switzerland": "CH",
    "austria": "AT",
    "belgium": "BE",
    "spain": "ES",
    "italy": "IT",
    "czech": "CZ",
    "ukraine": "UA",
    "brazil": "BR",
    "mexico": "MX",
}

# Regex: standalone 2-letter country code (DE, FI, NL, US) surrounded by
# non-alpha boundaries. Matches patterns like "DE-01", "US-1", "[DE]", "NL01".
_CODE_RE = re.compile(
    r"(?:^|[^A-Z])(DE|FI|NL|US|GB|FR|JP|SG|CA|AU|KR|HK|TW|IN|RU|TR|IR|PL|SE|CH|AT|BE|ES|IT|CZ|UA|BR|MX)(?:[^A-Z]|$)",
    re.IGNORECASE,
)


def detect_country(remark: str) -> str | None:
    """Detect a 2-letter ISO country code from a remark string.

    Tries in order:
    1. Flag emoji match (🇩🇪 → DE)
    2. Full country name (case-insensitive)
    3. Standalone 2-letter code (DE, US-01, [FI])

    Returns ``None`` if no country could be determined.
    """
    if not remark:
        return None

    # 1. Emoji flags (highest confidence).
    for emoji, code in _EMOJI_TO_CODE.items():
        if emoji in remark:
            return code

    lower = remark.lower()

    # 2. Full country names.
    for name, code in _NAME_TO_CODE.items():
        if name in lower:
            return code

    # 3. Standalone 2-letter codes.
    m = _CODE_RE.search(remark)
    if m:
        return m.group(1).upper()

    return None


def filter_by_country(configs: list, allowed: list[str]) -> list:
    """Filter configs to only those whose remark matches an allowed country.

    Args:
        configs: List of Config objects with a ``remark`` field.
        allowed: List of 2-letter country codes (e.g. ``["DE", "FI", "NL", "US"]``).
            Empty list = no filtering (return all).

    Returns filtered list. Configs get ``country`` set when detected.
    """
    if not allowed:
        return configs

    allowed_upper = {c.upper() for c in allowed}
    result = []
    for cfg in configs:
        if cfg.country is None:
            cfg.country = detect_country(cfg.remark)
        if cfg.country and cfg.country in allowed_upper:
            result.append(cfg)
    return result
