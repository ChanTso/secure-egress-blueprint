"""Structural checks for rendered reference configurations."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

PROTECTED_DESTINATIONS = frozenset(
    {
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:2::/48",
        "2001:10::/28",
        "2001:20::/28",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "fc00::/7",
        "fec0::/10",
        "fe80::/10",
        "ff00::/8",
    }
)
XRAY_MINIMUM_VERSION = "26.5.3"


def load_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return document


def _is_loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _blocked_destinations(document: dict[str, Any]) -> set[str]:
    routing = document.get("routing", {})
    rules = routing.get("rules", []) if isinstance(routing, dict) else []
    blocked: set[str] = set()
    for rule in rules if isinstance(rules, list) else []:
        if isinstance(rule, dict) and rule.get("outboundTag") == "blocked":
            ips = rule.get("ip", [])
            if isinstance(ips, list):
                blocked.update(str(item) for item in ips)
    return blocked


def _tagged_outbound(document: dict[str, Any], tag: str) -> dict[str, Any] | None:
    outbounds = document.get("outbounds", [])
    if not isinstance(outbounds, list):
        return None
    for outbound in outbounds:
        if isinstance(outbound, dict) and outbound.get("tag") == tag:
            return outbound
    return None


def _final_block_rule(document: dict[str, Any]) -> dict[str, Any] | None:
    outbound = _tagged_outbound(document, "egress")
    if outbound is None or outbound.get("protocol") != "freedom":
        return None
    settings = outbound.get("settings")
    if not isinstance(settings, dict) or settings.get("domainStrategy") != "UseIP":
        return None
    rules = settings.get("finalRules")
    if not isinstance(rules, list) or not rules or not isinstance(rules[0], dict):
        return None
    return rules[0]


def _routing_policy_is_ordered(document: dict[str, Any]) -> bool:
    routing = document.get("routing")
    if not isinstance(routing, dict):
        return False
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return False
    protected_index: int | None = None
    egress_index: int | None = None
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        inbound_tags = rule.get("inboundTag")
        applies_to_tunnel = not isinstance(inbound_tags, list) or "tunnel" in inbound_tags
        if (
            protected_index is None
            and rule.get("outboundTag") == "blocked"
            and applies_to_tunnel
            and isinstance(rule.get("ip"), list)
            and PROTECTED_DESTINATIONS <= {str(item) for item in rule["ip"]}
        ):
            protected_index = index
        if egress_index is None and rule.get("outboundTag") == "egress" and applies_to_tunnel:
            egress_index = index
    return (
        protected_index is not None and egress_index is not None and protected_index < egress_index
    )


def check_destination_blocklist(document: dict[str, Any]) -> list[str]:
    missing = sorted(PROTECTED_DESTINATIONS - _blocked_destinations(document))
    if missing:
        return ["special-use destination blocklist is incomplete"]
    return []


def check_server_config(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    inbounds = document.get("inbounds", [])
    if not isinstance(inbounds, list) or not inbounds:
        return ["server config requires at least one inbound"]

    for inbound in inbounds:
        if not isinstance(inbound, dict):
            errors.append("every inbound must be an object")
            continue
        listen = inbound.get("listen")
        if not isinstance(listen, str) or not _is_loopback(listen):
            errors.append("every Xray inbound must listen on loopback")

    errors.extend(check_destination_blocklist(document))

    routing = document.get("routing", {})
    strategy = routing.get("domainStrategy") if isinstance(routing, dict) else None
    if strategy not in {"IPIfNonMatch", "IPOnDemand"}:
        errors.append("routing must resolve domains before final IP policy checks")
    if not _routing_policy_is_ordered(document):
        errors.append("protected routing rule must precede the tunnel egress rule")

    version = document.get("version")
    if not isinstance(version, dict) or version.get("min") != XRAY_MINIMUM_VERSION:
        errors.append(f"Xray minimum version must be {XRAY_MINIMUM_VERSION}")

    outbounds = document.get("outbounds")
    if (
        not isinstance(outbounds, list)
        or not outbounds
        or not isinstance(outbounds[0], dict)
        or outbounds[0].get("protocol") != "blackhole"
    ):
        errors.append("the default server outbound must be blackhole")

    final_rule = _final_block_rule(document)
    if final_rule is None:
        errors.append("freedom egress requires a first final block rule after IP resolution")
    else:
        final_ips = final_rule.get("ip")
        if (
            final_rule.get("action") != "block"
            or final_rule.get("network") != "tcp,udp"
            or not isinstance(final_ips, list)
            or not PROTECTED_DESTINATIONS <= {str(item) for item in final_ips}
        ):
            errors.append("freedom final protected-address blocklist is incomplete")
    return errors


def check_client_config(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    outbounds = document.get("outbounds", [])
    if not isinstance(outbounds, list) or not outbounds:
        return ["client config requires an outbound"]
    protocols = {
        item.get("protocol")
        for item in outbounds
        if isinstance(item, dict) and isinstance(item.get("protocol"), str)
    }
    if "freedom" in protocols:
        errors.append("synthetic client config must not contain a direct fallback")
    if "vless" not in protocols:
        errors.append("synthetic client config requires the tunnel outbound")
    errors.extend(check_destination_blocklist(document))
    return errors


def _is_loopback_caddy_upstream(value: str) -> bool:
    candidate = value.split("://", maxsplit=1)[-1]
    if candidate.startswith("["):
        closing = candidate.find("]")
        if closing < 0 or candidate[closing + 1 : closing + 2] != ":":
            return False
        host = candidate[1:closing]
        port = candidate[closing + 2 :]
    else:
        if candidate.count(":") != 1:
            return False
        host, port = candidate.rsplit(":", maxsplit=1)
    try:
        return ipaddress.ip_address(host).is_loopback and 1 <= int(port) <= 65535
    except ValueError:
        return False


def _caddy_proxies_only_to_loopback(text: str) -> bool:
    found_proxy = False
    for line in text.splitlines():
        tokens = line.strip().split()
        if not tokens or tokens[0] != "reverse_proxy":
            continue
        found_proxy = True
        upstreams = tokens[1:]
        if upstreams and upstreams[0].startswith("@"):
            upstreams = upstreams[1:]
        upstreams = [upstream for upstream in upstreams if upstream != "{"]
        if not upstreams or any(
            not _is_loopback_caddy_upstream(upstream) for upstream in upstreams
        ):
            return False
    return found_proxy


def check_caddyfile(text: str) -> list[str]:
    errors: list[str] = []
    if "egress.example.com" not in text:
        errors.append("Caddy example must use the reserved example domain")
    if not _caddy_proxies_only_to_loopback(text):
        errors.append("Caddy must proxy only to a loopback Xray listener")
    if "respond 404" not in text:
        errors.append("unknown paths must be rejected")
    return errors
