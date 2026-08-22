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

from src.parsers.base import Config

logger = logging.getLogger(__name__)

#: Networks Mihomo expresses via <network>-opts; anything else falls back to
#: plain TCP transport. httpupgrade is translated to ws with
#: ``v2ray-http-upgrade`` (Mihomo has no network of its own for it).
_SUPPORTED_NETWORKS = {"ws", "grpc", "h2", "httpupgrade", "xhttp"}


def _name(cfg: Config, used: set[str]) -> str:
    base = str(cfg.remark or "").strip() or f"{cfg.address}:{cfg.port}"
    name = base
    suffix = 2
    while name in used:
        name = f"{base} #{suffix}"
        suffix += 1
    used.add(name)
    return name


def _tls_fields(cfg: Config, proxy: dict[str, Any]) -> None:
    security = str(cfg.security or "").lower()
    if security not in ("tls", "reality"):
        return
    proxy["tls"] = True
    if cfg.sni:
        proxy["servername"] = cfg.sni
    elif cfg.host:
        proxy["servername"] = str(cfg.host).split(",")[0].strip()
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
        if not cfg.pbk:
            return
        reality: dict[str, Any] = {"public-key": cfg.pbk}
        if cfg.sid:
            reality["short-id"] = cfg.sid
        proxy["reality-opts"] = reality
        proxy["client-fingerprint"] = cfg.fp or "chrome"


def _transport_fields(cfg: Config, proxy: dict[str, Any]) -> None:
    network = str(cfg.network or "tcp").lower()
    if network == "splithttp":
        network = "xhttp"
    if network not in _SUPPORTED_NETWORKS:
        return
    if network == "httpupgrade":
        # Mihomo rides httpupgrade on the ws transport behind a flag.
        proxy["network"] = "ws"
        opts: dict[str, Any] = {"v2ray-http-upgrade": True}
        if cfg.path:
            opts["path"] = cfg.path
        if cfg.host:
            opts["headers"] = {"Host": str(cfg.host).split(",")[0].strip()}
        proxy["ws-opts"] = opts
        return
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
        if cfg.path:
            opts["grpc-service-name"] = cfg.path.lstrip("/")
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


def config_to_clash_proxy(cfg: Config, used_names: set[str]) -> dict[str, Any] | None:
    """Convert one Config into a Mihomo proxy entry, or ``None``.

    ``None`` means "not expressible" — the config is skipped in the YAML
    output instead of corrupting the whole document for every other entry.
    """
    if not cfg.address or not cfg.port or not cfg.uuid_or_password:
        return None
    protocol = str(cfg.protocol or "").lower()
    proxy: dict[str, Any] = {
        "name": _name(cfg, used_names),
        "server": cfg.address,
        "port": int(cfg.port),
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
        proxy["alterId"] = int(cfg.alter_id or 0)
        proxy["cipher"] = "auto"
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
    elif protocol in ("hysteria2", "hy2"):
        proxy["type"] = "hysteria2"
        proxy["password"] = cfg.uuid_or_password
        # Hysteria2Option/TuicOption take "sni"; they have no "tls"/
        # "servername" fields (unknown keys are silently dropped, which
        # used to lose the SNI for every QUIC entry).
        if cfg.sni:
            proxy["sni"] = cfg.sni
        proxy["skip-cert-verify"] = True
        return proxy
    elif protocol == "tuic":
        credential = str(cfg.uuid_or_password or "")
        uuid_part, separator, password_part = credential.partition(":")
        if not separator:
            return None
        proxy["type"] = "tuic"
        proxy["uuid"] = uuid_part.strip()
        proxy["password"] = password_part.strip()
        if cfg.sni:
            proxy["sni"] = cfg.sni
        proxy["skip-cert-verify"] = True
        return proxy
    else:
        return None

    _tls_fields(cfg, proxy)
    _transport_fields(cfg, proxy)
    return proxy


def configs_to_clash(configs: list[Config]) -> list[dict[str, Any]]:
    """Convert configs to Mihomo proxy entries, skipping inexpressible ones."""
    used: set[str] = set()
    proxies: list[dict[str, Any]] = []
    for cfg in configs:
        if not cfg.raw_link:
            continue
        proxy = config_to_clash_proxy(cfg, used)
        if proxy is not None:
            proxies.append(proxy)
    return proxies


def write_clash_subscription(configs: list[Config], output_file: str) -> int:
    """Write the Mihomo YAML document; returns the proxy count."""
    proxies = configs_to_clash(configs)
    document: dict[str, Any] = {"proxies": proxies}
    try:
        with open(output_file, "w", encoding="utf-8", newline="\n") as fh:
            yaml.safe_dump(
                document,
                fh,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
    except OSError as exc:
        logger.warning("Cannot write Clash subscription %s: %s", output_file, exc)
        return 0
    return len(proxies)
