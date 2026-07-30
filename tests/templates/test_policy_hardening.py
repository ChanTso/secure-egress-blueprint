from __future__ import annotations

import json
from pathlib import Path

import jinja2
import yaml

from secure_egress.config_checks import PROTECTED_DESTINATIONS

REPOSITORY_ROOT = Path(__file__).parents[2]
ROLE_ROOT = REPOSITORY_ROOT / "ansible" / "roles" / "secure_egress"


def template_context() -> dict[str, object]:
    context = yaml.safe_load((ROLE_ROOT / "defaults" / "main.yml").read_text(encoding="utf-8"))
    context.update(
        yaml.safe_load(
            (REPOSITORY_ROOT / "ansible" / "group_vars" / "all.yml").read_text(encoding="utf-8")
        )
    )
    context.update(
        yaml.safe_load(
            (REPOSITORY_ROOT / "ansible" / "secrets" / "runtime.example.yml").read_text(
                encoding="utf-8"
            )
        )
    )
    return context


def render(name: str, **overrides: object) -> str:
    environment = jinja2.Environment(  # noqa: S701
        loader=jinja2.FileSystemLoader(ROLE_ROOT / "templates"),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
    )
    environment.filters["to_json"] = json.dumps
    context = template_context()
    context.update(overrides)
    return environment.get_template(name).render(**context)


def blocked_destinations(document: dict[str, object]) -> set[str]:
    routing = document["routing"]
    assert isinstance(routing, dict)
    rules = routing["rules"]
    assert isinstance(rules, list)
    for rule in rules:
        if isinstance(rule, dict) and rule.get("outboundTag") == "blocked":
            addresses = rule.get("ip")
            assert isinstance(addresses, list)
            return {str(address) for address in addresses}
    raise AssertionError("missing blocked route")


def test_server_and_client_use_the_checked_special_use_policy():
    server = json.loads(render("xray.json.j2"))
    client = json.loads(
        (REPOSITORY_ROOT / "examples" / "client" / "xray-client.synthetic.json").read_text(
            encoding="utf-8"
        )
    )
    assert blocked_destinations(server) == PROTECTED_DESTINATIONS
    assert blocked_destinations(client) == PROTECTED_DESTINATIONS
    assert {"::/128", "ff00::/8", "240.0.0.0/4"} <= PROTECTED_DESTINATIONS


def test_caddy_tls_listener_uses_the_configured_port():
    default_render = render("Caddyfile.j2")
    override_render = render("Caddyfile.j2", secure_egress_tls_port=8443)
    assert "egress.example.com:443 {" in default_render
    assert "egress.example.com:8443 {" in override_render
    assert "egress.example.com:443 {" not in override_render
