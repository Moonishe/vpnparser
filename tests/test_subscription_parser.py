"""Tests for subscription parsing of compressed (zlib/gzip/raw-deflate) payloads.

The decompressor tries several wrappers; a regression that silently killed the
zlib/raw-deflate candidates (passing an unsupported ``max_length`` kwarg that
``zlib.decompress`` rejects) must stay red, so each flavour is covered here.
"""

import base64
import gzip
import zlib

from src.parsers.subscription import SubscriptionParser


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode()


def _raw_deflate(payload: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(payload) + co.flush()


_SAMPLE = "vless://u@1.2.3.4:443?type=tcp#A\nvmess://eyJ9@5.6.7.8:443#B\n"


def test_plain_text_subscription() -> None:
    assert len(SubscriptionParser().parse_subscription(_SAMPLE)) == 2


def test_subscription_scheme_prefix_stripped() -> None:
    assert len(SubscriptionParser().parse_subscription("subscription:" + _SAMPLE)) == 2


def test_zlib_wrapped_subscription() -> None:
    assert (
        len(
            SubscriptionParser().parse_subscription(
                _b64(zlib.compress(_SAMPLE.encode()))
            )
        )
        == 2
    )


def test_gzip_wrapped_subscription() -> None:
    assert (
        len(
            SubscriptionParser().parse_subscription(
                _b64(gzip.compress(_SAMPLE.encode()))
            )
        )
        == 2
    )


def test_raw_deflate_wrapped_subscription() -> None:
    assert (
        len(
            SubscriptionParser().parse_subscription(
                _b64(_raw_deflate(_SAMPLE.encode()))
            )
        )
        == 2
    )


def test_empty_subscription_yields_no_links() -> None:
    assert SubscriptionParser().parse_subscription("") == []
    assert SubscriptionParser().parse_subscription(None) == []


def test_percent_encoded_base64_padding_still_decodes() -> None:
    """``%3D`` padding must not cost the whole subscription.

    The single-link decoder in base.py unquotes the payload before decoding;
    the subscription decoder used to decode strictly and lost the entire blob
    when the padding was percent-encoded.
    """
    links = [
        "vless://u@real-server.net:443?type=tcp#A",
        "trojan://secret@real-server.net:443#CD",
    ]
    blob = base64.b64encode("\n".join(links).encode()).decode("ascii")
    assert blob.endswith("==")  # the sample must actually carry padding
    quoted = blob[:-2] + "%3D%3D"

    parser = SubscriptionParser()
    assert parser.is_subscription(quoted) is True
    assert parser.parse_subscription(quoted) == links


def test_oversized_decompress_is_dropped_not_crashing() -> None:
    # A zlib stream whose output exceeds the safety cap must not raise out of
    # parse_subscription; the oversized candidate is dropped and we fall back
    # to plain-text decoding (which yields no links here).
    # Craft one that actually expands: store uncompressed via raw deflate of
    # zeros, sized just above the 32 MiB decompression cap.
    co = zlib.compressobj(0, zlib.DEFLATED, -15)
    bomb = co.compress(b"\x00" * (32 * 1024 * 1024 + 1)) + co.flush()
    # parse_subscription should return without raising.
    assert isinstance(SubscriptionParser().parse_subscription(_b64(bomb)), list)
