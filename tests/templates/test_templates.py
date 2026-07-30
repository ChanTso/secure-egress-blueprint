from __future__ import annotations

import json
from pathlib import Path

import jinja2
import yaml

from secure_egress.config_checks import (
    PROTECTED_DESTINATIONS,
    check_caddyfile,
    check_client_config,
    check_server_config,
)

REPOSITORY_ROOT = Path(__file__).parents[2]
ROLE_ROOT = REPOSITORY_ROOT / "ansible" / "roles" / "secure_egress"


def template_context() -> dict[str, object]:
    context = yaml.safe_load((ROLE_ROOT / "defaults" / "main.yml").read_text())
    context.update(
        yaml.safe_load((REPOSITORY_ROOT / "ansible" / "group_vars" / "all.yml").read_text())
    )
    context.update(
        yaml.safe_load(
            (REPOSITORY_ROOT / "ansible" / "secrets" / "runtime.example.yml").read_text()
        )
    )
    return context


def render(name: str, **overrides: object) -> str:
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(ROLE_ROOT / "templates"),
        autoescape=jinja2.select_autoescape(),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
    )
    environment.filters["to_json"] = json.dumps
    context = template_context()
    context.update(overrides)
    return environment.get_template(name).render(**context)


def test_caddy_template_has_exact_tunnel_path_and_fail_closed_fallback():
    rendered = render("Caddyfile.j2")
    assert check_caddyfile(rendered) == []
    assert all(
        line.strip().startswith("reverse_proxy 127.0.0.1:")
        for line in rendered.splitlines()
        if line.strip().startswith("reverse_proxy")
    )
    assert "\t\tpath /synthetic-tunnel\n" in rendered
    assert "/synthetic-tunnel*" not in rendered
    assert "http://127.0.0.1:19080" in rendered
    assert rendered.count("respond 404") == 2
    assert "admin off" in rendered
    assert "tls internal" in rendered


def test_xray_template_is_loopback_only_and_default_blackhole():
    document = json.loads(render("xray.json.j2"))
    assert check_server_config(document) == []
    assert {inbound["tag"] for inbound in document["inbounds"]} == {"tunnel", "api"}
    assert all(inbound["listen"] == "127.0.0.1" for inbound in document["inbounds"])
    assert document["outbounds"][0] == {
        "tag": "blocked",
        "protocol": "blackhole",
    }
    blocked = next(
        rule for rule in document["routing"]["rules"] if rule.get("outboundTag") == "blocked"
    )
    assert set(blocked["ip"]) == PROTECTED_DESTINATIONS
    assert blocked["inboundTag"] == ["tunnel"]
    assert document["version"] == {"min": "26.5.3", "max": ""}
    egress = next(outbound for outbound in document["outbounds"] if outbound["tag"] == "egress")
    final_rule = egress["settings"]["finalRules"][0]
    assert final_rule["action"] == "block"
    assert final_rule["network"] == "tcp,udp"
    assert set(final_rule["ip"]) == PROTECTED_DESTINATIONS


def test_xray_template_uses_only_the_external_synthetic_identifier():
    document = json.loads(render("xray.json.j2"))
    clients = document["inbounds"][0]["settings"]["clients"]
    assert clients == [
        {
            "id": "00000000-0000-4000-8000-000000000001",
            "level": 0,
        }
    ]


def test_traffic_guard_template_is_decision_only_by_default():
    document = json.loads(render("traffic-guard.json.j2"))
    assert document["auto_stop_enabled"] is False
    assert document["stop_acknowledgement"] == ""
    assert document["stats_endpoint"] == "127.0.0.1:11085"
    assert document["query_user"] == "xray"
    service = render("secure-egress-traffic-guard.service.j2")
    assert " --enforce" not in service


def test_traffic_guard_enforce_flag_requires_explicit_render_setting():
    service = render(
        "secure-egress-traffic-guard.service.j2",
        secure_egress_traffic_guard_enforce=True,
    )
    assert "--enforce" in service


def test_every_service_unit_contains_the_hardening_baseline():
    baseline = {
        "NoNewPrivileges=true",
        "PrivateDevices=true",
        "PrivateTmp=true",
        "ProtectHome=true",
        "ProtectKernelModules=true",
        "ProtectKernelTunables=true",
        "ProtectSystem=strict",
        "RestrictNamespaces=true",
        "RestrictSUIDSGID=true",
        "LockPersonality=true",
        "UMask=0077",
    }
    names = [
        "secure-egress-caddy.service.j2",
        "secure-egress-xray.service.j2",
        "secure-egress-traffic-guard.service.j2",
    ]
    for name in names:
        unit_lines = set(render(name).splitlines())
        assert baseline <= unit_lines


def test_synthetic_client_has_no_direct_fallback():
    path = REPOSITORY_ROOT / "examples" / "client" / "xray-client.synthetic.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert check_client_config(document) == []
    protocols = {outbound["protocol"] for outbound in document["outbounds"]}
    assert protocols == {"vless", "blackhole"}
    assert all(inbound["listen"] == "127.0.0.1" for inbound in document["inbounds"])
