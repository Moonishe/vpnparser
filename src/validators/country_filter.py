"""Country detection from config remark/server name.

Many public VPN configs include country indicators in their display names:
- Flag emojis: 🇩🇪 🇫🇮 🇳🇱 🇺🇸
- Country codes: DE, FI, NL, US, DE-01, USA-02
- Country names: Germany, Finland, Netherlands, USA

This module extracts a 2-letter ISO country code from the remark string
**without any network calls** — instant for hundreds of thousands of configs.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.parsers.base import Config

logger = logging.getLogger(__name__)

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
    # NOTE: "us" and "uk" removed — too many false positives ("contact us", "about us").
    # US/GB are detected via _CODE_RE (uppercase) and emoji flags.
    "uk": "GB",
    "united kingdom": "GB",
    "england": "GB",
    "france": "FR",
    "japan": "JP",
    "canada": "CA",
    "australia": "AU",
    "korea": "KR",
    "south korea": "KR",
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
    "indonesia": "ID",
    "thailand": "TH",
    "vietnam": "VN",
    "philippines": "PH",
    "malaysia": "MY",
    "uae": "AE",
    "united arab emirates": "AE",
    "emirates": "AE",
    "south africa": "ZA",
    "argentina": "AR",
}

# --- city name → ISO code ---
# VPN configs frequently use city names in remarks instead of country codes.
_CITY_TO_CODE: dict[str, str] = {
    # Germany
    "frankfurt": "DE",
    "munich": "DE",
    "munchen": "DE",
    "berlin": "DE",
    "hamburg": "DE",
    "cologne": "DE",
    "koln": "DE",
    "dusseldorf": "DE",
    "stuttgart": "DE",
    "nuremberg": "DE",
    "nurnberg": "DE",
    # Finland
    "helsinki": "FI",
    "tampere": "FI",
    "turku": "FI",
    "espoo": "FI",
    # Netherlands
    "amsterdam": "NL",
    "rotterdam": "NL",
    "the hague": "NL",
    "den haag": "NL",
    "eindhoven": "NL",
    "utrecht": "NL",
    # USA
    "new york": "US",
    "newyork": "US",
    "nyc": "US",
    "los angeles": "US",
    "la": "US",
    "miami": "US",
    "seattle": "US",
    "chicago": "US",
    "dallas": "US",
    "washington": "US",
    "san jose": "US",
    "san francisco": "US",
    "francisco": "US",
    "san diego": "US",
    "phoenix": "US",
    "denver": "US",
    "atlanta": "US",
    "houston": "US",
    "boston": "US",
    "philly": "US",
    "philadelphia": "US",
    "vegas": "US",
    "las vegas": "US",
    "new jersey": "US",
    "nj": "US",
    "virginia": "US",
    "va": "US",
    "oregon": "US",
    "ohio": "US",
    "texas": "US",
    "tx": "US",
    "california": "US",
    "ca": "US",
    "florida": "US",
    "fl": "US",
    # UK
    "london": "GB",
    "manchester": "GB",
    "glasgow": "GB",
    # France
    "paris": "FR",
    "marseille": "FR",
    "lyon": "FR",
    # Japan
    "tokyo": "JP",
    "osaka": "JP",
    # Singapore
    "singapore": "SG",
    # Canada
    "toronto": "CA",
    "montreal": "CA",
    "vancouver": "CA",
    # Australia
    "sydney": "AU",
    "melbourne": "AU",
    # Korea
    "seoul": "KR",
    # Hong Kong
    "hong kong": "HK",
    "hongkong": "HK",
    "hkg": "HK",
    # Taiwan
    "taipei": "TW",
    "taiwan": "TW",
    # Russia
    "moscow": "RU",
    "москва": "RU",
    "saint petersburg": "RU",
    "petersburg": "RU",
    "spb": "RU",
    # Turkey
    "istanbul": "TR",
    # Poland
    "warsaw": "PL",
    "warszawa": "PL",
    # Sweden
    "stockholm": "SE",
    # Switzerland
    "zurich": "CH",
    "geneva": "CH",
    # Austria
    "vienna": "AT",
    "wien": "AT",
    # Spain
    "madrid": "ES",
    "barcelona": "ES",
    # Italy
    "rome": "IT",
    "milan": "IT",
    "milano": "IT",
    # Czech
    "prague": "CZ",
    "praha": "CZ",
    # Indonesia
    "jakarta": "ID",
    # Thailand
    "bangkok": "TH",
    # Vietnam
    "hanoi": "VN",
    "ho chi minh": "VN",
    "saigon": "VN",
    # Philippines
    "manila": "PH",
    # Malaysia
    "kuala lumpur": "MY",
    "kl": "MY",
    # UAE
    "dubai": "AE",
    "abu dhabi": "AE",
    # South Africa
    "johannesburg": "ZA",
    # Argentina
    "buenos aires": "AR",
}

# --- single source of truth for supported country codes ---
# _CODE_RE and _HOST_COUNTRY_RE are auto-generated from this tuple.
# _EMOJI_TO_CODE, _NAME_TO_CODE, _CITY_TO_CODE are independent hardcoded
# dicts — their values should be a subset of _SUPPORTED_CODES (verified
# at import time below).  Adding a new country means appending one line
# here AND adding entries to the relevant dicts above.
_SUPPORTED_CODES: tuple[str, ...] = (
    "DE",
    "FI",
    "NL",
    "US",
    "GB",
    "FR",
    "JP",
    "SG",
    "CA",
    "AU",
    "KR",
    "HK",
    "TW",
    "IN",
    "RU",
    "TR",
    "IR",
    "PL",
    "SE",
    "CH",
    "AT",
    "BE",
    "ES",
    "IT",
    "CZ",
    "UA",
    "BR",
    "MX",
    "ID",
    "TH",
    "VN",
    "PH",
    "MY",
    "AE",
    "ZA",
    "AR",
)

# Codes that double as common English words / abbreviations when uppercased
# (US, IN, ID, AT, BE, IT, MY, ES) or as ordinal suffixes (TH → "5TH").
# These need a *structural delimiter* right after the code (hyphen, digit,
# bracket, pipe, slash) — otherwise "CONTACT US", "SERVER ID", "SIGN IN",
# "5TH FLOOR", "MY SERVER", "DO IT" are misread as countries.
_AMBIGUOUS_CODES: frozenset[str] = frozenset(
    {"US", "IN", "ID", "AT", "BE", "IT", "MY", "TH", "ES"}
)

# Import-time sanity check: every value in the detection dicts must be a
# supported code, otherwise detect_country() could return a code that
# filter_by_country() would silently drop.  This makes the "subset of
# _SUPPORTED_CODES" promise enforced rather than merely documented.
_DICT_VALUES = (
    set(_EMOJI_TO_CODE.values())
    | set(_NAME_TO_CODE.values())
    | set(_CITY_TO_CODE.values())
)
_UNKNOWN_DICT_CODES = _DICT_VALUES - set(_SUPPORTED_CODES)
if _UNKNOWN_DICT_CODES:
    raise RuntimeError(
        "country_filter: detection dict maps to code(s) not in "
        f"_SUPPORTED_CODES: {sorted(_UNKNOWN_DICT_CODES)}"
    )

# Safe codes = supported minus ambiguous.  A 2-letter combo like "DE" or
# "JP" is never a common English word, so any standalone uppercased
# occurrence is the country and the loose non-alpha boundary rule is safe.
_SAFE_CODES = tuple(c for c in _SUPPORTED_CODES if c not in _AMBIGUOUS_CODES)

# Regex: standalone 2-letter country code (DE, FI, NL, ...) surrounded by
# non-alpha boundaries. Matches "DE-01", "[DE]", "NL01", "JP server".
# Case-SENSITIVE (no IGNORECASE) — otherwise common English words match:
# "in" → IN, "at" → AT, "be" → BE, "es" → ES.  VPN remarks use UPPERCASE
# codes (DE-01, [FI]).  Only SAFE codes use this loose boundary rule.
_CODE_RE = re.compile(
    r"(?:^|[^A-Za-z])(" + "|".join(_SAFE_CODES) + r")(?:[^A-Za-z]|$)",
)

# Ambiguous codes: same case-sensitive boundaries, but the code MUST be
# immediately followed by a structural delimiter — hyphen, digit, closing
# bracket/paren, pipe, or slash.  Accepts "US-01", "ID01", "[US]", "US|DE",
# "US/01" and rejects "CONTACT US", "SERVER ID", "SIGN IN", "5TH FLOOR",
# "MY SERVER", "DO IT" (code followed by space or end-of-string).
_AMBIGUOUS_CODE_RE = re.compile(
    r"(?:^|[^A-Za-z])(" + "|".join(_AMBIGUOUS_CODES) + r")(?=[-\d\]/|)])",
)

# Hostname prefix patterns: de01.vpn.com, nl-ams.vpn.net, us01.server.net
# Matches a 2-letter country code at the start of a hostname segment.
# Case-insensitive — hostnames are case-insensitive.
# Safe codes accept hyphen-or-digit after (nl-ams, de01); ambiguous codes
# require a DIGIT after, so reverse DNS "in-addr.arpa", "my-server.",
# "it-support." don't false-positive as IN / MY / IT.  Ambiguous codes
# with a hyphen (e.g. "id-jakarta") are still detected via the city regex.
_HOST_COUNTRY_RE = re.compile(
    r"(?:^|\.|[-_])(" + "|".join(_SAFE_CODES) + r")[-\d]",
    re.IGNORECASE,
)
_HOST_AMBIGUOUS_RE = re.compile(
    r"(?:^|\.|[-_])(" + "|".join(_AMBIGUOUS_CODES) + r")\d",
    re.IGNORECASE,
)

# Precompiled word-boundary regexes for city and country-name matching.
# Sorting alternatives by length (descending) ensures longer names are
# preferred when multiple could match at the same position (e.g.
# "los angeles" before "la").  The ``\b`` anchors prevent substring false
# positives like "la" in "flash", "us" in "trust", "paris" in "parisian",
# or "rome" in "romero".
_CITY_PATTERN = re.compile(
    r"\b("
    + "|".join(re.escape(city) for city in sorted(_CITY_TO_CODE, key=len, reverse=True))
    + r")\b",
    re.IGNORECASE,
)

_NAME_PATTERN = re.compile(
    r"\b("
    + "|".join(re.escape(name) for name in sorted(_NAME_TO_CODE, key=len, reverse=True))
    + r")\b",
    re.IGNORECASE,
)


def detect_country(remark: str, *extra_fields: str | None) -> str | None:
    """Detect a 2-letter ISO country code from a remark string.

    Tries in order:
    1. Flag emoji (🇩🇪 → DE)
    2. City names (frankfurt, amsterdam, tokyo...)
    3. Full country names (germany, usa, russia...)
    4. Standalone 2-letter code (DE, US-01, [FI])
    5. Hostname country prefix (de01.vpn.com, us-east.server.net)

    All non-empty text fields (remark + extra_fields) are combined into a
    single string so each regex runs **once** instead of once per field.
    A ``\\n`` separator prevents cross-field false positives (no city or
    country name spans a newline, and ``\\b`` word-boundaries treat ``\\n``
    as a non-word character).

    Returns ``None`` if no country could be determined.
    """
    # Early exit only if there is nothing to search at all — both the remark
    # and all extra_fields are empty/None.  When the remark is empty but
    # extra_fields (e.g. address, sni) contain a country indicator, we must
    # still run the hostname-based detection below.
    if not remark and not any(f for f in extra_fields if f):
        return None

    # Combine all non-empty text fields into one string.
    # "\n" separator: safe for \b-anchored regexes and substring checks.
    # Filter out None/empty to avoid TypeError in str.join().
    texts = [t for t in [remark, *extra_fields] if t]
    combined = "\n".join(texts)

    # 1. Emoji flags (highest confidence).
    for emoji, code in _EMOJI_TO_CODE.items():
        if emoji in combined:
            return code

    # 2. City names — single regex search on combined text.
    m = _CITY_PATTERN.search(combined)
    if m:
        return _CITY_TO_CODE[m.group(1).lower()]

    # 3. Full country names — single regex search on combined text.
    m = _NAME_PATTERN.search(combined)
    if m:
        return _NAME_TO_CODE[m.group(1).lower()]

    # 4. Standalone 2-letter codes — check remark first (most reliable).
    #    Safe codes (DE, JP, NL ...) use the loose boundary rule; ambiguous
    #    codes (US, IN, ID, AT, BE, IT, MY, TH, ES) require a structural
    #    delimiter after, to avoid "CONTACT US" / "SERVER ID" / "5TH FLOOR".
    if remark:
        m = _CODE_RE.search(remark) or _AMBIGUOUS_CODE_RE.search(remark)
        if m:
            return m.group(1).upper()

    # 5. Hostname country prefix — check address/sni/host.
    #    Ambiguous codes require a digit after (not hyphen) so that reverse
    #    DNS like "in-addr.arpa" or "my-server.example.com" don't match.
    for field in extra_fields:
        if field:
            m = _HOST_COUNTRY_RE.search(field) or _HOST_AMBIGUOUS_RE.search(field)
            if m:
                return m.group(1).upper()

    return None


def filter_by_country(configs: list[Config], allowed: list[str]) -> list[Config]:
    """Filter configs to only those whose remark matches an allowed country.

    Args:
        configs: List of Config objects with a ``remark`` field.
        allowed: List of 2-letter country codes (e.g. ``["DE", "FI", "NL", "US"]``).
            Empty list = no filtering (return all).

    Returns filtered list. Configs get ``country`` set when detected.

    Raises a warning (never an exception) if ``allowed`` contains codes not in
    :data:`_SUPPORTED_CODES` — such codes will never match because
    :func:`detect_country` only returns codes from that set.  This catches
    typos in ``settings.yaml`` (e.g. ``"UK"`` instead of ``"GB"``).
    """
    if not allowed:
        return configs

    allowed_upper = {c.upper() for c in allowed}

    # Warn about unsupported codes — they silently never match, which is a
    # common misconfiguration (e.g. "UK" vs "GB", "USA" vs "US").
    invalid = allowed_upper - set(_SUPPORTED_CODES)
    if invalid:
        logger.warning(
            "allowed_countries contains code(s) not supported by "
            "detect_country: %s — these will never match any config. "
            "Supported codes: %s",
            ", ".join(sorted(invalid)),
            ", ".join(_SUPPORTED_CODES),
        )

    result = []
    for cfg in configs:
        if cfg.country is None:
            cfg.country = detect_country(
                cfg.remark,
                getattr(cfg, "address", None),
                getattr(cfg, "sni", None),
                getattr(cfg, "host", None),
            )
        if cfg.country and cfg.country in allowed_upper:
            result.append(cfg)
    return result
