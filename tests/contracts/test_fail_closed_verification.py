from __future__ import annotations

from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]
FAIL_CLOSED = REPOSITORY_ROOT / "ansible" / "roles" / "secure_egress" / "tasks" / "fail_closed.yml"
MANAGED_UNITS = {
    "secure-egress-caddy.service",
    "secure-egress-xray.service",
    "secure-egress-traffic-guard.service",
    "secure-egress-traffic-guard.timer",
}


def test_fail_closed_requests_and_verifies_every_managed_unit():
    tasks = yaml.safe_load(FAIL_CLOSED.read_text(encoding="utf-8"))
    assert len(tasks) == 6
    stop_task, active_task, active_assert, enabled_task, enabled_assert, pointer_task = tasks

    assert set(stop_task["loop"]) == MANAGED_UNITS
    assert stop_task["ansible.builtin.systemd_service"] == {
        "name": "{{ item }}",
        "enabled": False,
        "state": "stopped",
    }
    assert stop_task["failed_when"] is False

    assert set(active_task["loop"]) == MANAGED_UNITS
    assert active_task["ansible.builtin.command"]["argv"][:2] == [
        "/usr/bin/systemctl",
        "is-active",
    ]
    assert active_task["failed_when"] is False
    assert "secure_egress_fail_closed_active.results" in active_assert["loop"]

    assert set(enabled_task["loop"]) == MANAGED_UNITS
    assert enabled_task["ansible.builtin.command"]["argv"][:2] == [
        "/usr/bin/systemctl",
        "is-enabled",
    ]
    assert enabled_task["failed_when"] is False
    assert "secure_egress_fail_closed_enabled.results" in enabled_assert["loop"]

    assert pointer_task["ansible.builtin.file"]["state"] == "absent"
    assert "failed_when" not in pointer_task


def test_verification_treats_missing_units_as_safe_but_not_active_or_enabled():
    text = FAIL_CLOSED.read_text(encoding="utf-8")
    assert "'unknown'" in text
    assert "'not-found'" in text
    assert "'active'" not in text
    assert "'enabled'" not in text
    assert "Fail-closed verification could not prove" in text
