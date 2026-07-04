"""Parser package — exports all protocol parsers."""

from src.parsers.base import BaseParser, Config, find_all_links, safe_b64decode
from src.parsers.vmess import VmessParser
from src.parsers.vless import VlessParser
from src.parsers.trojan import TrojanParser
from src.parsers.shadowsocks import ShadowsocksParser
from src.parsers.subscription import SubscriptionParser

ALL_PARSERS: list[BaseParser] = [
    VmessParser(),
    VlessParser(),
    TrojanParser(),
    ShadowsocksParser(),
]

__all__ = [
    "BaseParser",
    "Config",
    "ALL_PARSERS",
    "find_all_links",
    "safe_b64decode",
    "VmessParser",
    "VlessParser",
    "TrojanParser",
    "ShadowsocksParser",
    "SubscriptionParser",
]
