from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]
ROLE_ROOT = REPOSITORY_ROOT / "ansible" / "roles" / "secure_egress"


def test_synthetic_tls_is_internal_only_across_ansible_and_firewall_layers():
    defaults = yaml.safe_load((ROLE_ROOT / "defaults" / "main.yml").read_text(encoding="utf-8"))
    public_vars = yaml.safe_load(
        (REPOSITORY_ROOT / "ansible" / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    preflight = (ROLE_ROOT / "tasks" / "preflight.yml").read_text(encoding="utf-8")
    caddy = (ROLE_ROOT / "templates" / "Caddyfile.j2").read_text(encoding="utf-8")
    firewall = (
        REPOSITORY_ROOT / "infra" / "tofu" / "modules" / "egress-node" / "main.tf"
    ).read_text(encoding="utf-8")

    assert "secure_egress_tls_mode" not in defaults
    assert "secure_egress_tls_mode" not in public_vars
    assert "secure_egress_tls_mode" not in preflight
    assert "tls internal" in caddy
    assert "managed" not in caddy
    assert "from_port = 443" in firewall
    assert "from_port = 80" not in firewall
