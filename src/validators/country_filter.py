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
    # NOTE: "us" is NOT in this map — too many false positives ("contact us",
    # "about us"); US is detected via _CODE_RE (uppercase) and emoji flags.
    # "uk" IS mapped explicitly: a bare lowercase "uk" token in a remark is
    # unambiguous enough to be worth a GB match (the stale comment above it
    # used to claim both were removed while "uk" sat right below).
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
    {"US", "IN", "ID", "AT", "BE", "IT", "MY", "TH", "ES"},
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
        f"_SUPPORTED_CODES: {sorted(_UNKNOWN_DICT_CODES)}",
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
    r"(?:^|[^A-Za-z])(" + "|".join(_AMBIGUOUS_CODES) + r")(?=[-\d\]/|._])",
)

# An ambiguous code that reads as a common word collides with its word
# meaning even behind a delimiter: "SERVER-ID-07" is *identifier #7*, not
# Indonesia.  When "ID" directly follows another bare word (separated by a
# delimiter), it is an ordinal label — skip that occurrence and keep looking.
# Only "ID" gets this treatment: "server-US-01" genuinely means a US server,
# and dropping it would cost far more than the rare misread costs.
_PRECEDING_WORD_TAIL_RE = re.compile(r"[A-Za-z]{2,}\Z")
_ID_DELIMITER_CHARS = " -_[|(/"

# Every ISO 3166-1 alpha-2 code (249). Used ONLY to recognise stamps of
# countries outside _SUPPORTED_CODES (e.g. "NO-01" on a Norwegian server):
# the country filter would drop such configs after a lookup anyway, so the
# capped API budget is spent on them last. Never assigned as a *kept*
# country — only detect_country() (supported codes) does that.
_ALL_ISO_CODES: tuple[str, ...] = (
    "AD",
    "AE",
    "AF",
    "AG",
    "AI",
    "AL",
    "AM",
    "AO",
    "AQ",
    "AR",
    "AS",
    "AT",
    "AU",
    "AW",
    "AX",
    "AZ",
    "BA",
    "BB",
    "BD",
    "BE",
    "BF",
    "BG",
    "BH",
    "BI",
    "BJ",
    "BL",
    "BM",
    "BN",
    "BO",
    "BQ",
    "BR",
    "BS",
    "BT",
    "BV",
    "BW",
    "BY",
    "BZ",
    "CA",
    "CC",
    "CD",
    "CF",
    "CG",
    "CH",
    "CI",
    "CK",
    "CL",
    "CM",
    "CN",
    "CO",
    "CR",
    "CU",
    "CV",
    "CW",
    "CX",
    "CY",
    "CZ",
    "DE",
    "DJ",
    "DK",
    "DM",
    "DO",
    "DZ",
    "EC",
    "EE",
    "EG",
    "EH",
    "ER",
    "ES",
    "ET",
    "FI",
    "FJ",
    "FK",
    "FM",
    "FO",
    "FR",
    "GA",
    "GB",
    "GD",
    "GE",
    "GF",
    "GG",
    "GH",
    "GI",
    "GL",
    "GM",
    "GN",
    "GP",
    "GQ",
    "GR",
    "GS",
    "GT",
    "GU",
    "GW",
    "GY",
    "HK",
    "HM",
    "HN",
    "HR",
    "HT",
    "HU",
    "ID",
    "IE",
    "IL",
    "IM",
    "IN",
    "IO",
    "IQ",
    "IR",
    "IS",
    "IT",
    "JE",
    "JM",
    "JO",
    "JP",
    "KE",
    "KG",
    "KH",
    "KI",
    "KM",
    "KN",
    "KP",
    "KR",
    "KW",
    "KY",
    "KZ",
    "LA",
    "LB",
    "LC",
    "LI",
    "LK",
    "LR",
    "LS",
    "LT",
    "LU",
    "LV",
    "LY",
    "MA",
    "MC",
    "MD",
    "ME",
    "MF",
    "MG",
    "MH",
    "MK",
    "ML",
    "MM",
    "MN",
    "MO",
    "MP",
    "MQ",
    "MR",
    "MS",
    "MT",
    "MU",
    "MV",
    "MW",
    "MX",
    "MY",
    "MZ",
    "NA",
    "NC",
    "NE",
    "NF",
    "NG",
    "NI",
    "NL",
    "NO",
    "NP",
    "NR",
    "NU",
    "NZ",
    "OM",
    "PA",
    "PE",
    "PF",
    "PG",
    "PH",
    "PK",
    "PL",
    "PM",
    "PN",
    "PR",
    "PS",
    "PT",
    "PW",
    "PY",
    "QA",
    "RE",
    "RO",
    "RS",
    "RU",
    "RW",
    "SA",
    "SB",
    "SC",
    "SD",
    "SE",
    "SG",
    "SH",
    "SI",
    "SJ",
    "SK",
    "SL",
    "SM",
    "SN",
    "SO",
    "SR",
    "SS",
    "ST",
    "SV",
    "SX",
    "SY",
    "SZ",
    "TC",
    "TD",
    "TF",
    "TG",
    "TH",
    "TJ",
    "TK",
    "TL",
    "TM",
    "TN",
    "TO",
    "TR",
    "TT",
    "TV",
    "TW",
    "TZ",
    "UA",
    "UG",
    "UM",
    "US",
    "UY",
    "UZ",
    "VA",
    "VC",
    "VE",
    "VG",
    "VI",
    "VN",
    "VU",
    "WF",
    "WS",
    "YE",
    "YT",
    "ZA",
    "ZM",
    "ZW",
)

# Import-time guard against typos in the table above: every supported code
# must be a real ISO code, otherwise _FOREIGN_CODE_RE silently misses it.
_MISSING_ISO_CODES = set(_SUPPORTED_CODES) - set(_ALL_ISO_CODES)
if _MISSING_ISO_CODES:
    raise RuntimeError(
        "country_filter: supported code(s) missing from _ALL_ISO_CODES: "
        f"{sorted(_MISSING_ISO_CODES)}",
    )

_FOREIGN_CODES: tuple[str, ...] = tuple(
    code for code in _ALL_ISO_CODES if code not in _SUPPORTED_CODES
)

# Unsupported-but-valid ISO stamps: the strict ambiguous-code discipline
# (case-sensitive uppercase, non-alpha left boundary, structural delimiter
# right after) — "NO-01", "[NO]", "NO|DE" match, "NO LOGS" does not.
_FOREIGN_CODE_RE = re.compile(
    r"(?:^|[^A-Za-z])(" + "|".join(_FOREIGN_CODES) + r")(?=[-\d\]/|._])",
)


def remark_names_unsupported_country(remark: str | None) -> str | None:
    """Return a valid ISO-3166 code outside ``_SUPPORTED_CODES`` from *remark*.

    Remark-only and delimiter-strict by design: bare words ("NO LOGS")
    never match, only stamps ("NO-01"). Hostname stamps are deliberately
    out of scope — reverse-DNS noise needs its own rule set, and a missed
    stamp only costs API-budget priority, never correctness.

    Callers use this to deprioritize (not skip) rate-limited GeoIP lookups
    the country filter would drop after the lookup anyway.
    """
    if not remark or not isinstance(remark, str):
        return None
    match = _FOREIGN_CODE_RE.search(remark)
    return match.group(1).upper() if match else None


# Hostname prefix patterns: de01.vpn.com, nl-ams.vpn.net, us-east.server.net
# Matches a 2-letter country code at the start of a hostname segment.
# Case-insensitive — hostnames are case-insensitive.
# Safe codes accept hyphen-or-digit-or-dot after (nl-ams, de01, ru.) — the dot
# covers domain-style stamps like "ru.store.x.com" where nothing follows the
# code but another label; ambiguous codes require a DIGIT after, so reverse
# DNS "in-addr.arpa", "my-server.", "it-support." don't false-positive as
# IN / MY / IT.  Ambiguous codes with a hyphen (e.g. "id-jakarta") are still
# detected via the city regex.
_HOST_COUNTRY_RE = re.compile(
    r"(?:^|\.|[-_])(" + "|".join(_SAFE_CODES) + r")[-\d.]",
    re.IGNORECASE,
)
# Ambiguous codes in hostnames must start a segment, carry no lettered
# prefix, and be followed by digits that END WITHIN the segment (a hyphen or
# more digits then a hyphen — "us1-node", "us-01"): a bare "us1."/"id2.host"
# is indistinguishable from instance numbering ("id2.host.net", "it3.pop.net"
# were read as Indonesia / Italy), so the segment-final stamp form is
# deliberately not matched for the ambiguous set — the safe codes (DE, NL…)
# keep covering it, and remarks cover the rest.
_HOST_AMBIGUOUS_RE = re.compile(
    r"(?:^|\.)([a-z0-9-]*?)(" + "|".join(_AMBIGUOUS_CODES) + r")(?:\d|-|_|\.)",
    re.IGNORECASE,
)
# A non-empty leading prefix inside the same label ("cdn" in "cdn-in1")
# vetoes the match: real stamps are bare ("us1-node").
_HOST_AMBIGUOUS_PREFIX_RE = re.compile(r"[a-z]", re.IGNORECASE)

# Two-letter city/state abbreviations ("la", "tx", "nj", ...) are far too
# short for a case-insensitive \b-search over remark+address+sni+host: they hit
# hostname labels ("vpn.example.ca" -> California, "proxy.host.la" -> US) and
# ordinary words ("Casa de la Montaña" -> US).  They are therefore matched
# separately: remark-only, and framed by structural delimiters on both sides.
# Keys that are also supported country codes ("ca" -> Canada) are excluded
# outright, so a remark like "CA-01" cannot flip between Canada and California
# depending on its case.
_SHORT_CITY_KEYS = tuple(
    sorted(
        key
        for key in _CITY_TO_CODE
        if len(key) <= 2 and key.upper() not in _SUPPORTED_CODES
    ),
)
_LONG_CITY_KEYS = tuple(
    sorted((key for key in _CITY_TO_CODE if len(key) > 2), key=len, reverse=True),
)

# Precompiled word-boundary regexes for city and country-name matching.
# Sorting alternatives by length (descending) ensures longer names are
# preferred when multiple could match at the same position (e.g.
# "los angeles" before "hong kong").  The ``\b`` anchors prevent substring
# false positives like "us" in "trust", "paris" in "parisian", or "rome" in
# "romero".
_CITY_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(city) for city in _LONG_CITY_KEYS) + r")\b",
    re.IGNORECASE,
)

# Delimiter-anchored on BOTH sides, case-insensitive: matches "LA-01", "[tx]",
# "server-la-01", "NJ01" and rejects ".ca", "de la", "kl.example.com", "Kl
# node".  Case matters far less than structure here — lowercase remarks like
# "server-la-01" are as common as uppercase ones, while a plain-prose "la"
# never carries a hyphen or bracket around it.
_SHORT_CITY_RE = re.compile(
    r"(?:^|[-|\[(/])("
    + "|".join(re.escape(key) for key in _SHORT_CITY_KEYS)
    + r")(?=[-\d\]/|)]|$)",
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
    2. Explicit 2-letter code in the remark (DE, US-01, [FI])
    3. City names of 3+ characters (frankfurt, amsterdam, tokyo...)
    4. Full country names (germany, usa, russia...)
    5. Two-letter city/state abbreviation in the remark (LA-01, [TX])
    6. Hostname country prefix (de01.vpn.com, ru.store.x.com)

    The explicit remark code outranks city/name matches: hostings routinely
    embed their POP city into hostnames ("de01.frankfurt.hoster.net" fronting
    a Dutch server), so a city match in address/sni must never override an
    operator-stamped code in the remark.

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

    # 2. Explicit 2-letter codes in the remark — most reliable signal.
    #    Safe codes (DE, JP, NL ...) use the loose boundary rule; ambiguous
    #    codes (US, IN, ID, AT, BE, IT, MY, TH, ES) require a structural
    #    delimiter after, to avoid "CONTACT US" / "SERVER ID" / "5TH FLOOR".
    #    An "ID" directly following another word ("SERVER-ID-07") is an
    #    ordinal identifier, not Indonesia: skip that occurrence.
    if remark:
        m = _CODE_RE.search(remark)
        if m:
            return m.group(1).upper()
        for m in _AMBIGUOUS_CODE_RE.finditer(remark):
            if m.group(1).upper() == "ID":
                head = remark[: m.start()].rstrip(_ID_DELIMITER_CHARS)
                if head and _PRECEDING_WORD_TAIL_RE.search(head):
                    continue
            return m.group(1).upper()

    # 3. City names (3+ chars) — single regex search on combined text.
    m = _CITY_PATTERN.search(combined)
    if m:
        return _CITY_TO_CODE[m.group(1).lower()]

    # 4. Full country names — single regex search on combined text.
    m = _NAME_PATTERN.search(combined)
    if m:
        return _NAME_TO_CODE[m.group(1).lower()]

    # 5. Two-letter city/state abbreviations — remark only, uppercase, and
    #    delimiter-anchored.  Runs after the country codes so "CA-01" is read
    #    as Canada rather than California.
    if remark:
        m = _SHORT_CITY_RE.search(remark)
        if m:
            return _CITY_TO_CODE[m.group(1).lower()]

    # 6. Hostname country prefix — check address/sni/host.
    #    Ambiguous codes must start a segment and may not carry a lettered
    #    prefix inside it (see the regex comment): "us1." / "us1-node" match,
    #    "cdn-in1" / "id2" do not.
    for field in extra_fields:
        if not field:
            continue
        m = _HOST_COUNTRY_RE.search(field)
        if m:
            return m.group(1).upper()
        for m in _HOST_AMBIGUOUS_RE.finditer(field):
            if _HOST_AMBIGUOUS_PREFIX_RE.search(m.group(1)):
                continue
            # "my-server" is English, not Malaysia: a '-' right after the
            # code with no digit anywhere in the same dot-label is prose
            # ("my-server", "in-house", "it-support"), not a country stamp
            # ("us-01", "us1-node"). Genuine hyphen stamps without digits
            # ("id-jakarta") still resolve via the city regex on combined.
            delimiter = m.group(0)[-1] if m.group(0) else ""
            if delimiter == "-":
                seg_start = field.rfind(".", 0, m.start(2)) + 1
                seg_end = field.find(".", m.end(2))
                if seg_end == -1:
                    seg_end = len(field)
                label = field[seg_start:seg_end]
                if not any(ch.isdigit() for ch in label):
                    continue
            return m.group(2).upper()

    return None


def normalize_country_code(value: str | None) -> str | None:
    """Return *value* as an uppercased supported ISO code, or ``None``.

    Single source of truth for validating country hints that come from
    configuration (``sources.json`` ``default_country``) before they are
    stamped onto a :class:`Config`.  Only a 2-letter alphabetic code from
    :data:`_SUPPORTED_CODES` is accepted: anything else (``"USA"``,
    ``"CURACAO"``, ``"XX"``, ``"12"``) would otherwise leak into
    ``Config.country`` and produce bogus location files and filter verdicts.
    """
    if value is None:
        return None
    text = str(value).strip().upper()
    if len(text) == 2 and text.isalpha() and text in _SUPPORTED_CODES:
        return text
    return None


def filter_by_country(configs: list[Config], allowed: list[str] | None) -> list[Config]:
    """Filter configs to only those whose remark matches an allowed country.

    Args:
        configs: List of Config objects with a ``remark`` field.
        allowed: List of 2-letter country codes (e.g. ``["DE", "FI", "NL", "US"]``).
            Empty list = no filtering (return all). ``None`` is rejected — a
            missing list must not silently disable the filter (fail-open).

    Returns filtered list. Configs get ``country`` set when detected.

    Raises:
        ValueError: if ``allowed`` is ``None`` — callers must pass an explicit
            list (``[]`` disables filtering).

    Raises a warning (never an exception) if ``allowed`` contains codes not in
    :data:`_SUPPORTED_CODES` — such codes will never match because
    :func:`detect_country` only returns codes from that set.  This catches
    typos in ``settings.yaml`` (e.g. ``"UK"`` instead of ``"GB"``).
    """
    if allowed is None:
        raise ValueError(
            "filter_by_country requires an explicit allowed list; "
            "pass [] to disable filtering rather than None."
        )
    if not allowed:
        return configs

    allowed_upper = {str(c).strip().upper() for c in allowed}

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
        if cfg.country and str(cfg.country).strip().upper() in allowed_upper:
            result.append(cfg)
    return result
