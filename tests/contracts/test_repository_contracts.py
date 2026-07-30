from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]


def read(path: str) -> str:
    return (REPOSITORY_ROOT / path).read_text(encoding="utf-8")


def test_opentofu_is_default_disabled_and_has_no_world_open_ingress():
    variables = read("infra/tofu/variables.tf")
    main = read("infra/tofu/main.tf")
    module_variables = read("infra/tofu/modules/egress-node/variables.tf")
    module_main = read("infra/tofu/modules/egress-node/main.tf")
    providers = read("infra/tofu/providers.tf")
    assert re.search(
        r'variable "deployment_enabled"\s*\{.*?default\s*=\s*false',
        variables,
        re.DOTALL,
    )
    assert variables.count('tonumber(split("/", cidr)[1]) > 0') >= 2
    assert variables.count('split("/", cidr)[0] == cidrhost(cidr, 0)') >= 2
    assert "count  = var.deployment_enabled ? 1 : 0" in main
    assert 'check "deployment_interlock"' not in main
    assert "deployment_authorized = (" in main
    assert 'variable "deployment_authorized"' in module_variables
    assert "condition     = var.deployment_authorized" in module_variables
    assert "skip_metadata_api_check     = true" in providers
    assert 'ip_address_type   = "ipv4"' in module_main


def test_ansible_defaults_are_non_deploying_and_non_enforcing():
    defaults = yaml.safe_load(read("ansible/roles/secure_egress/defaults/main.yml"))
    public = yaml.safe_load(read("ansible/group_vars/all.yml"))
    for values in (defaults, public):
        assert values["secure_egress_deployment_enabled"] is False
        assert values["secure_egress_traffic_guard_auto_stop_enabled"] is False
        assert values["secure_egress_traffic_guard_enforce"] is False


def test_secret_vars_are_external_and_secret_tasks_suppress_output():
    ansible_ignore = read("ansible/.gitignore")
    secret_ignore = read("ansible/secrets/.gitignore")
    preflight = read("ansible/roles/secure_egress/tasks/preflight.yml")
    stage = read("ansible/roles/secure_egress/tasks/stage.yml")
    assert "secrets/*.yml" in ansible_ignore
    assert "*.yml" in secret_ignore
    assert "0600" in stage
    assert preflight.count("no_log: true") >= 2
    assert stage.count("no_log: true") >= 5


def test_transaction_has_validation_atomic_switch_health_and_rollback():
    stage = read("ansible/roles/secure_egress/tasks/stage.yml")
    activate = read("ansible/roles/secure_egress/tasks/activate.yml")
    health = read("ansible/roles/secure_egress/tasks/health.yml")
    rollback = read("ansible/roles/secure_egress/tasks/rollback.yml")
    fail_closed = read("ansible/roles/secure_egress/tasks/fail_closed.yml")
    main = read("ansible/roles/secure_egress/tasks/main.yml")
    assert "validate" in stage
    assert "-test" in stage
    assert "checksum_algorithm: sha256" in stage
    assert "| hash('sha256')" in stage
    assert "--no-target-directory" in activate
    assert "include_tasks: health.yml" in activate
    assert "127.0.0.1" in health
    assert "/healthz" in health
    assert "rescue:" in main
    assert "Atomically restore the previous release" in rollback
    assert "Stop and disable services when no rollback target exists" in rollback
    assert "Remove the failed or indeterminate current pointer" in fail_closed


def test_xray_server_routes_are_fail_closed_by_structure():
    template = read("ansible/roles/secure_egress/templates/xray.json.j2")
    assert template.index('"protocol": "blackhole"') < template.index('"protocol": "freedom"')
    assert '"listen": "127.0.0.1"' in template
    assert '"169.254.0.0/16"' in template
    assert '"outboundTag": "egress"' in template


def test_offline_tofu_validator_allowlists_only_init_and_validate():
    script = read("scripts/validate-tofu-offline.sh")
    assert "init | validate)" in script
    assert "init -backend=false -input=false" in script
    assert "run_safe_tofu validate -no-color" in script
    assert "AWS_EC2_METADATA_DISABLED=true" in script
    invocations = re.findall(r"^run_safe_tofu ([a-z-]+)", script, re.MULTILINE)
    assert invocations == ["init", "validate"]


def test_validate_script_contains_only_local_quality_gates():
    script = read("scripts/validate.sh")
    required = [
        "ruff check .",
        "pytest --cov",
        "shellcheck",
        "yamllint",
        "ansible-playbook --syntax-check",
        "ansible-lint",
        "tofu fmt -check",
        "validate-tofu-offline.sh",
        "secure_egress.privacy_lint",
        "gitleaks git .",
        "build --no-isolation",
    ]
    assert all(gate in script for gate in required)
    assert "aws " not in script


def test_synthetic_traffic_guard_fixture_is_dry_run():
    fixture = json.loads(read("examples/traffic-guard.synthetic.json"))
    assert fixture["auto_stop_enabled"] is False
    assert fixture["stop_acknowledgement"] == ""
    assert fixture["stats_endpoint"].startswith("127.0.0.1:")
