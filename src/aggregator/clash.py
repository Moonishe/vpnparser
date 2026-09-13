"""Clash/Mihomo YAML subscription output.

The base64 link list serves v2rayN-style clients; the Clash family
(Clash.Meta / Mihomo / Stash) consumes a YAML ``proxies:`` document. This
module converts validated Configs into Mihomo proxy entries — same input
pool, same order, so the YAML twin never publishes a config the base64
subscription does not.
"""

from __future__ import annotations

import logging
from typing import Any

import yaml

from src.parsers.base import _UUID_RE, Config
from src.utils.paths import write_text_atomic

logger = logging.getLogger(__name__)

#: Networks Mihomo expresses via <network>-opts; anything else falls back to
#: plain TCP transport. httpupgrade is translated to ws with
#: ``v2ray-http-upgrade`` (Mihomo has no network of its own for it).
#:
#: The allowed set is per protocol, per the Mihomo proxy docs
#: (wiki.metacubex.one/en/config/proxies/{vless,vmess,trojan}): vless rides
#: ws/h2/grpc/xhttp, vmess ws/h2/grpc (no xhttp), trojan only ws/grpc. An
#: unsupported value is silently ignored by Mihomo ("TCP is used"), i.e. a
#: dead entry — so it must be skipped here. httpupgrade is listed wherever the
#: ws transport it compiles to is allowed.
_SUPPORTED_NETWORKS_BY_PROTOCOL: dict[str, set[str]] = {
    "vless": {"ws", "grpc", "h2", "xhttp", "httpupgrade"},
    "vmess": {"ws", "grpc", "h2", "httpupgrade"},
    "trojan": {"ws", "grpc", "httpupgrade"},
}


def _name(cfg: Config, used: set[str]) -> str:
    base = str(cfg.remark or "").strip() or f"{cfg.address}:{cfg.port}"
    # Remarks come from untrusted subscription links: an embedded CR/LF
    # would break the YAML line (or inject a second key) via safe_dump.
    base = base.replace("\r", " ").replace("\n", " ")
    name = base
    suffix = 2
    while name in used:
        name = f"{base} #{suffix}"
        suffix += 1
    used.add(name)
    return name


def _tls_fields(
    cfg: Config,
    proxy: dict[str, Any],
    *,
    sni_key: str = "servername",
) -> bool:
    """Fill TLS/Reality fields; ``False`` = not expressible (skip the config).

    Reality without a public key cannot be expressed in Mihomo: publishing
    it as plain TLS would hand out an entry that can never handshake, while
    the Xray probe fail-closes the same case.

    ``sni_key`` names the SNI field of the target Mihomo option: vless/vmess
    use ``servername``, while trojan uses ``sni`` (its ``TrojanOption`` has no
    ``servername``; unknown keys are silently dropped, which used to lose the
    SNI for every trojan entry).
    """
    security = str(cfg.security or "").lower()
    if security not in ("tls", "reality"):
        return True
    if security == "reality" and not cfg.pbk:
        return False
    proxy["tls"] = True
    if cfg.sni and str(cfg.sni).strip():
        proxy[sni_key] = str(cfg.sni).strip()
    elif cfg.host and str(cfg.host).split(",")[0].strip():
        proxy[sni_key] = str(cfg.host).split(",")[0].strip()
    if cfg.alpn:
        alpn = [
            part.strip()
            for part in str(cfg.alpn).replace(";", ",").split(",")
            if part.strip()
        ]
        if alpn:
            proxy["alpn"] = alpn
    # Free-list certificates are self-signed as a rule; the pipeline's own
    # TLS stage is equally non-verifying.
    proxy["skip-cert-verify"] = True
    if security == "reality":
        reality: dict[str, Any] = {"public-key": cfg.pbk}
        if cfg.sid:
            reality["short-id"] = cfg.sid
        proxy["reality-opts"] = reality
        proxy["client-fingerprint"] = cfg.fp or "chrome"
    return True


def _transport_fields(cfg: Config, proxy: dict[str, Any], protocol: str) -> bool:
    """Fill transport opts; ``False`` = not expressible (skip the config).

    Plain ``tcp`` needs no key (Mihomo default). Unknown non-TCP networks
    (legacy ``kcp``/``http``) used to fall through as plain TCP and hand
    out dead entries — skip them instead. The same holds for a network the
    protocol does not carry (``xhttp`` on vmess/trojan): Mihomo ignores the
    value and dials plain TCP, so publishing it hands out a dead entry.
    """
    network = str(cfg.network or "tcp").lower()
    if network == "splithttp":
        network = "xhttp"
    if network == "tcp":
        return True
    allowed = _SUPPORTED_NETWORKS_BY_PROTOCOL.get(str(protocol or "").lower())
    # A protocol missing from the table has no known-good network: skip
    # rather than guess.
    if allowed is None or network not in allowed:
        return False
    if network == "httpupgrade":
        # Mihomo rides httpupgrade on the ws transport behind a flag.
        proxy["network"] = "ws"
        opts: dict[str, Any] = {"v2ray-http-upgrade": True}
        if cfg.path:
            opts["path"] = cfg.path
        if cfg.host:
            opts["headers"] = {"Host": str(cfg.host).split(",")[0].strip()}
        proxy["ws-opts"] = opts
        return True
    proxy["network"] = network
    if network == "ws":
        opts = {}
        if cfg.path:
            opts["path"] = cfg.path
        if cfg.host:
            opts["headers"] = {"Host": str(cfg.host).split(",")[0].strip()}
        proxy["ws-opts"] = opts
    elif network == "grpc":
        opts = {}
        if cfg.path and str(cfg.path).lstrip("/").strip():
            opts["grpc-service-name"] = str(cfg.path).lstrip("/").strip()
        proxy["grpc-opts"] = opts
    elif network == "h2":
        opts = {}
        if cfg.path:
            opts["path"] = cfg.path
        if cfg.host:
            hosts = [
                part.strip()
                for part in str(cfg.host).replace(";", ",").split(",")
                if part.strip()
            ]
            if hosts:
                opts["host"] = hosts
        proxy["h2-opts"] = opts
    elif network == "xhttp":
        opts = {}
        if cfg.path:
            opts["path"] = cfg.path
        if cfg.host:
            opts["host"] = str(cfg.host).split(",")[0].strip()
        proxy["xhttp-opts"] = opts
    return True


def config_to_clash_proxy(cfg: Config, used_names: set[str]) -> dict[str, Any] | None:
    """Convert one Config into a Mihomo proxy entry, or ``None``.

    ``None`` means "not expressible" — the config is skipped in the YAML
    output instead of corrupting the whole document for every other entry.
    """
    if not cfg.address or not cfg.port or not cfg.uuid_or_password:
        return None
    try:
        port = int(cfg.port)
    except (TypeError, ValueError):
        return None
    protocol = str(cfg.protocol or "").lower()
    # "name" is reserved LAST, at the return sites below: an inexpressible
    # config must not burn a name — skipped proxies used to leave holes in
    # the "base #2, #3, …" numbering.
    proxy: dict[str, Any] = {
        "server": cfg.address,
        "port": port,
    }
    if protocol == "vless":
        proxy["type"] = "vless"
        proxy["uuid"] = cfg.uuid_or_password
        if cfg.flow:
            proxy["flow"] = cfg.flow
        if cfg.fp:
            proxy["client-fingerprint"] = cfg.fp
    elif protocol == "vmess":
        proxy["type"] = "vmess"
        proxy["uuid"] = cfg.uuid_or_password
        try:
            proxy["alterId"] = int(cfg.alter_id or 0)
        except (TypeError, ValueError):
            return None
        proxy["cipher"] = "auto"
        if cfg.fp:
            # The probe validated the config with this uTLS fingerprint;
            # dropping it would change the JA3 handshake for picky servers.
            proxy["client-fingerprint"] = cfg.fp
    elif protocol == "trojan":
        proxy["type"] = "trojan"
        proxy["password"] = cfg.uuid_or_password
        if cfg.fp:
            proxy["client-fingerprint"] = cfg.fp
    elif protocol == "ss":
        if not cfg.ss_method:
            return None
        proxy["type"] = "ss"
        proxy["cipher"] = cfg.ss_method
        proxy["password"] = cfg.uuid_or_password
        # NOTE: a non-tcp `network` falls through to _transport_fields, which
        # has no "ss" row — on purpose. Mihomo's ShadowsocksOption carries no
        # `network` field (ws/grpc ride the `plugin` v2ray-plugin instead, a
        # different Config shape), so any transport value would be silently
        # ignored and the entry would dial plain TCP: skip rather than publish
        # a dead entry. The base64 twin keeps the link untouched.
    elif protocol in ("hysteria2", "hy2"):
        proxy["type"] = "hysteria2"
        proxy["password"] = cfg.uuid_or_password
        # Hysteria2Option/TuicOption take "sni"; they have no "tls"/
        # "servername" fields (unknown keys are silently dropped, which
        # used to lose the SNI for every QUIC entry).
        if cfg.sni and str(cfg.sni).strip():
            proxy["sni"] = str(cfg.sni).strip()
        # Salamander obfuscation fields: without them a server that requires
        # obfs rejects every client packet, i.e. the entry is dead on arrival.
        obfs = getattr(cfg, "obfs", None)
        if obfs:
            proxy["obfs"] = str(obfs)
        obfs_password = getattr(cfg, "obfs_password", None)
        if obfs_password:
            proxy["obfs-password"] = str(obfs_password)
        if cfg.alpn:
            alpn = [
                part.strip()
                for part in str(cfg.alpn).replace(";", ",").split(",")
                if part.strip()
            ]
            if alpn:
                proxy["alpn"] = alpn
        proxy["skip-cert-verify"] = True
        return {"name": _name(cfg, used_names), **proxy}
    elif protocol == "tuic":
        credential = str(cfg.uuid_or_password or "")
        uuid_part, separator, password_part = credential.partition(":")
        if not separator or not password_part.strip():
            # A separator-less v4 token has no uuid:password halves for
            # Mihomo (kept in the base64 twin for v4 clients).
            return None
        # A v4 token containing ":" is opaque, not a v5 uuid:password pair:
        # Mihomo needs a real uuid, so only UUID heads are expressible.
        if _UUID_RE.match(uuid_part.strip()) is None:
            return None
        proxy["type"] = "tuic"
        proxy["uuid"] = uuid_part.strip()
        proxy["password"] = password_part.strip()
        if cfg.sni and str(cfg.sni).strip():
            proxy["sni"] = str(cfg.sni).strip()
        # Mihomo TuicOption accepts alpn; the parser stores it (tuic.py) and
        # dropping it here made the tuic entry the only one losing ALPN.
        if cfg.alpn:
            alpn = [
                part.strip()
                for part in str(cfg.alpn).replace(";", ",").split(",")
                if part.strip()
            ]
            if alpn:
                proxy["alpn"] = alpn
        # Mihomo TuicOption carries both; parse stores them since 0.2.0.
        cc = getattr(cfg, "congestion_control", None)
        if cc:
            proxy["congestion-controller"] = str(cc)
        urm = getattr(cfg, "udp_relay_mode", None)
        if urm:
            proxy["udp-relay-mode"] = str(urm)
        proxy["skip-cert-verify"] = True
        return {"name": _name(cfg, used_names), **proxy}
    elif protocol == "shadowtls":
        # No standalone `shadowtls` proxy type in Mihomo: ShadowTLS there is
        # `type: ss + plugin: shadow-tls` (needs an inner SS cipher/password
        # this Config does not carry) or `shadow-tls-opts`. Emitting
        # `type: shadowtls` produced entries Mihomo drops (or a broken file),
        # so skip like other inexpressible protocols (wireguard, ...).
        return None
    elif protocol == "anytls":
        proxy["type"] = "anytls"
        proxy["password"] = cfg.uuid_or_password
        if cfg.sni and str(cfg.sni).strip():
            proxy["sni"] = str(cfg.sni).strip()
        if cfg.alpn:
            alpn = [
                part.strip()
                for part in str(cfg.alpn).replace(";", ",").split(",")
                if part.strip()
            ]
            if alpn:
                proxy["alpn"] = alpn
        proxy["skip-cert-verify"] = True
        return {"name": _name(cfg, used_names), **proxy}
    else:
        return None

    # trojan's Mihomo option names the SNI ``sni``; vless/vmess use
    # ``servername``. The QUIC-family branches above return early and write
    # ``sni`` themselves.
    sni_key = "sni" if protocol == "trojan" else "servername"
    if not _tls_fields(cfg, proxy, sni_key=sni_key):
        return None
    if not _transport_fields(cfg, proxy, protocol):
        return None
    return {"name": _name(cfg, used_names), **proxy}


def configs_to_clash(configs: list[Config]) -> list[dict[str, Any]]:
    """Convert configs to Mihomo proxy entries, skipping inexpressible ones.

    Dead configs (``is_alive is False``) are skipped for the same reason
    ``write_subscription`` skips them: the base64 twin must never publish a
    config the YAML twin refuses, and vice versa.
    """
    used: set[str] = set()
    proxies: list[dict[str, Any]] = []
    for cfg in configs:
        if not cfg.raw_link or cfg.is_alive is False:
            continue
        try:
            proxy = config_to_clash_proxy(cfg, used)
        except (ValueError, TypeError, AttributeError) as exc:
            logger.warning(
                "Skipping Clash-inexpressible config %s:%s (%s).",
                cfg.address,
                cfg.port,
                exc,
            )
            continue
        if proxy is not None:
            proxies.append(proxy)
    return proxies


def write_clash_subscription(configs: list[Config], output_file: str) -> int:
    """Write the Mihomo YAML document; returns the proxy count."""
    proxies = configs_to_clash(configs)
    document: dict[str, Any] = {"proxies": proxies}
    # Serialize then delegate to the atomic writer so a crash mid-write cannot
    # publish a broken YAML file.
    try:
        payload = yaml.safe_dump(
            document,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
    except (OSError, ValueError) as exc:
        logger.warning("Cannot serialize Clash subscription %s: %s", output_file, exc)
        return 0
    try:
        write_text_atomic(output_file, payload, encoding="utf-8")
    except OSError as exc:
        logger.warning("Cannot write Clash subscription %s: %s", output_file, exc)
        return 0
    return len(proxies)
