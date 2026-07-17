"""Parser package — exports all protocol parsers."""

from src.parsers.anytls import AnyTlsParser
from src.parsers.base import (
    BaseParser,
    Config,
    find_all_links,
    parse_password_host_port,
    safe_b64decode,
    split_host_port,
)
from src.parsers.hysteria2 import Hysteria2Parser
from src.parsers.shadowsocks import ShadowsocksParser
from src.parsers.shadowtls import ShadowTlsParser
from src.parsers.subscription import SubscriptionParser
from src.parsers.trojan import TrojanParser
from src.parsers.tuic import TuicParser
from src.parsers.vless import VlessParser
from src.parsers.vmess import VmessParser

ALL_PARSERS: list[BaseParser] = [
    VmessParser(),
    VlessParser(),
    TrojanParser(),
    ShadowsocksParser(),
    Hysteria2Parser(),
    TuicParser(),
    ShadowTlsParser(),
    AnyTlsParser(),
]

# O(1) scheme → parser dispatch table, built once at import.
# Replaces the O(N) linear scan over ALL_PARSERS in _parse_one_link: instead
# of calling can_parse() on every parser for every link (8 x N redundant
# strip+lower+startswith), the scheme is extracted once per link and the
# parser is found via a single dict lookup.
# Each parser's ``schemes`` ClassVar declares which URL schemes it handles
# (defaulting to ``(protocol,)``; Hysteria2Parser overrides to include "hy2").
PARSER_BY_SCHEME: dict[str, BaseParser] = {
    scheme: parser
    for parser in ALL_PARSERS
    for scheme in (parser.schemes or (parser.protocol,))
}

__all__ = [
    "ALL_PARSERS",
    "PARSER_BY_SCHEME",
    "AnyTlsParser",
    "BaseParser",
    "Config",
    "Hysteria2Parser",
    "ShadowTlsParser",
    "ShadowsocksParser",
    "SubscriptionParser",
    "TrojanParser",
    "TuicParser",
    "VlessParser",
    "VmessParser",
    "find_all_links",
    "parse_password_host_port",
    "safe_b64decode",
    "split_host_port",
]
