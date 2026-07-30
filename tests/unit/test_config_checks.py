from __future__ import annotations

import json

import pytest

from secure_egress.config_checks import (
    PROTECTED_DESTINATIONS,
    check_caddyfile,
    check_client_config,
    check_destination_blocklist,
    check_server_config,
    load_json,
)


def complete_block_rule() -> dict[str, object]:
    return {
        "outboundTag": "blocked",
        "ip": sorted(PROTECTED_DESTINATIONS),
    }


def complete_final_block_rule() -> dict[str, object]:
    return {
        "action": "block",
        "network": "tcp,udp",
        "ip": sorted(PROTECTED_DESTINATIONS),
    }


def valid_server_config() -> dict[str, object]:
    protected_rule = complete_block_rule()
    protected_rule["inboundTag"] = ["tunnel"]
    return {
        "inbounds": [{"listen": "127.0.0.1"}],
        "version": {"min": "26.5.3", "max": ""},
        "outbounds": [
            {"tag": "blocked", "protocol": "blackhole"},
            {
                "tag": "egress",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "UseIP",
                    "finalRules": [complete_final_block_rule()],
                },
            },
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                protected_rule,
                {
                    "inboundTag": ["tunnel"],
                    "network": "tcp,udp",
                    "outboundTag": "egress",
                },
            ],
        },
    }


def valid_client_config() -> dict[str, object]:
    return {
        "outbounds": [
            {"tag": "tunnel", "protocol": "vless"},
            {"tag": "blocked", "protocol": "blackhole"},
            {"protocol": 1},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [complete_block_rule()],
        },
    }


def test_load_json_requires_an_object(tmp_path):
    valid_path = tmp_path / "valid.json"
    valid_path.write_text('{"synthetic": true}\n', encoding="utf-8")
    assert load_json(valid_path) == {"synthetic": True}

    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_json(invalid_path)


def test_load_json_propagates_invalid_json(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_json(path)


def test_server_config_accepts_loopback_and_complete_blocklist():
    assert check_server_config(valid_server_config()) == []


@pytest.mark.parametrize("inbounds", [[], "not-a-list", None])
def test_server_config_requires_inbounds(inbounds):
    assert check_server_config({"inbounds": inbounds}) == [
        "server config requires at least one inbound"
    ]


def test_server_config_reports_non_objects_and_non_loopback_listeners():
    document = valid_server_config()
    document["inbounds"] = [
        "invalid",
        {"listen": "192.0.2.44"},
        {"listen": 127},
        {"listen": "not-an-address"},
    ]
    errors = check_server_config(document)
    assert "every inbound must be an object" in errors
    assert errors.count("every Xray inbound must listen on loopback") == 3


def test_server_config_reports_missing_blocklist_and_resolution_policy():
    document = {
        "inbounds": [{"listen": "127.0.0.1"}],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"outboundTag": "blocked", "ip": "not-a-list"},
                "not-an-object",
            ],
        },
    }
    errors = check_server_config(document)
    assert "special-use destination blocklist is incomplete" in errors
    assert "routing must resolve domains before final IP policy checks" in errors
    assert "protected routing rule must precede the tunnel egress rule" in errors
    assert "freedom egress requires a first final block rule after IP resolution" in errors


def test_server_config_handles_malformed_routing():
    errors = check_server_config(
        {
            "inbounds": [{"listen": "::1"}],
            "routing": "not-an-object",
        }
    )
    assert "protected routing rule must precede the tunnel egress rule" in errors
    assert "freedom egress requires a first final block rule after IP resolution" in errors


@pytest.mark.parametrize("strategy", ["IPIfNonMatch", "IPOnDemand"])
def test_server_config_accepts_both_safe_domain_strategies(strategy):
    document = valid_server_config()
    document["routing"]["domainStrategy"] = strategy  # type: ignore[index]
    assert check_server_config(document) == []


def test_server_config_rejects_missing_or_reordered_final_ip_policy():
    document = valid_server_config()
    egress = document["outbounds"][1]  # type: ignore[index]
    final_rule = egress["settings"]["finalRules"][0]  # type: ignore[index]
    final_rule["ip"].remove("169.254.0.0/16")  # type: ignore[union-attr]
    assert "freedom final protected-address blocklist is incomplete" in check_server_config(
        document
    )

    document = valid_server_config()
    egress = document["outbounds"][1]  # type: ignore[index]
    egress["settings"]["finalRules"].insert(0, {"action": "allow"})  # type: ignore[index]
    assert "freedom final protected-address blocklist is incomplete" in check_server_config(
        document
    )


def test_server_config_rejects_egress_before_protected_routing_and_old_xray():
    document = valid_server_config()
    document["routing"]["rules"].reverse()  # type: ignore[index]
    document["version"]["min"] = "26.5.2"  # type: ignore[index]
    errors = check_server_config(document)
    assert "protected routing rule must precede the tunnel egress rule" in errors
    assert "Xray minimum version must be 26.5.3" in errors


def test_destination_blocklist_requires_major_ipv4_and_ipv6_special_use_ranges():
    assert {
        "0.0.0.0/8",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "240.0.0.0/4",
        "::/128",
        "::ffff:0:0/96",
        "2001:db8::/32",
        "fc00::/7",
        "ff00::/8",
    } <= PROTECTED_DESTINATIONS
    document = {
        "routing": {
            "rules": [
                complete_block_rule(),
                {"outboundTag": "blocked", "ip": ["ff00::/8"]},
            ]
        }
    }
    assert check_destination_blocklist(document) == []
    document["routing"]["rules"] = []  # type: ignore[index]
    assert check_destination_blocklist(document) == [
        "special-use destination blocklist is incomplete"
    ]


def test_client_config_requires_an_outbound():
    assert check_client_config({}) == ["client config requires an outbound"]
    assert check_client_config({"outbounds": "invalid"}) == ["client config requires an outbound"]


def test_client_config_rejects_direct_fallback_and_requires_tunnel_and_policy():
    assert check_client_config({"outbounds": [{"protocol": "freedom"}, "invalid"]}) == [
        "synthetic client config must not contain a direct fallback",
        "synthetic client config requires the tunnel outbound",
        "special-use destination blocklist is incomplete",
    ]


def test_client_config_accepts_tunnel_blackhole_and_complete_policy():
    assert check_client_config(valid_client_config()) == []


def test_client_config_rejects_tunnel_with_incomplete_special_use_policy():
    document = valid_client_config()
    document["routing"] = {
        "domainStrategy": "IPIfNonMatch",
        "rules": [{"outboundTag": "blocked", "ip": ["127.0.0.0/8"]}],
    }
    assert check_client_config(document) == ["special-use destination blocklist is incomplete"]


def test_caddyfile_contract():
    valid = """
egress.example.com:443 {
    reverse_proxy 127.0.0.1:11080
    respond 404
}
"""
    assert check_caddyfile(valid) == []
    assert check_caddyfile("") == [
        "Caddy example must use the reserved example domain",
        "Caddy must proxy only to a loopback Xray listener",
        "unknown paths must be rejected",
    ]


def test_caddyfile_contract_rejects_remote_upstream():
    remote = """
egress.example.com:443 {
    reverse_proxy 198.51.100.44:11080
    respond 404
}
"""
    assert check_caddyfile(remote) == ["Caddy must proxy only to a loopback Xray listener"]


def test_caddyfile_contract_rejects_mixed_loopback_and_remote_upstreams():
    mixed = """
egress.example.com:443 {
    reverse_proxy 127.0.0.1:11080 203.0.113.44:11080
    respond 404
}
"""
    assert check_caddyfile(mixed) == ["Caddy must proxy only to a loopback Xray listener"]
