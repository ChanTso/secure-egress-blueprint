from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]
ROLE_TASKS = REPOSITORY_ROOT / "ansible" / "roles" / "secure_egress" / "tasks"


def read_task(name: str) -> str:
    return (ROLE_TASKS / name).read_text(encoding="utf-8")


def test_release_digest_preserves_fixed_file_to_checksum_order():
    stage = read_task("stage.yml")
    digest_section = stage.split(
        "- name: Derive the stable content digest",
        maxsplit=1,
    )[1]
    digest_section = digest_section.split(
        "- name: Inspect an existing identical release",
        maxsplit=1,
    )[0]
    assert "| sort" not in digest_section
    assert digest_section.count("| map(attribute='stat.checksum')") == 2
    assert digest_section.count("| join(':')") == 2


def test_ephemeral_staging_does_not_report_desired_state_drift():
    stage = read_task("stage.yml")
    pre_commit = stage.split("- name: Atomically commit a new immutable release", maxsplit=1)[0]
    assert pre_commit.count("changed_when: false") >= 7
    assert "Discard staging when an identical release already exists" in stage


def test_committed_service_configs_are_root_owned_and_group_read_only():
    stage = read_task("stage.yml")
    assert 'group: "{{ secure_egress_xray_group }}"\n    mode: "0640"' in stage
    assert 'group: "{{ secure_egress_caddy_group }}"\n    mode: "0640"' in stage
    assert 'dest: "{{ secure_egress_stage_path }}/traffic-guard.json"' in stage
    assert 'group: root\n    mode: "0600"' in stage


def test_same_digest_activation_skips_all_mutating_service_tasks():
    activate = read_task("activate.yml")
    assert "secure_egress_previous_release != secure_egress_release_path" in activate
    assert activate.count("when: secure_egress_activation_required | bool") >= 7
    health_section = activate.split(
        "- name: Verify Xray listeners and the Caddy health endpoint",
        maxsplit=1,
    )[1]
    assert "when: secure_egress_activation_required" not in health_section


def test_rollback_failure_always_enters_shared_fail_closed_tasks():
    rollback = read_task("rollback.yml")
    fail_closed = read_task("fail_closed.yml")
    assert "rescue:" in rollback
    assert rollback.count("include_tasks: fail_closed.yml") == 2
    assert "enabled: false" in fail_closed
    assert "state: stopped" in fail_closed
    assert "state: absent" in fail_closed


def test_activation_and_rollback_share_health_checks_and_rollback_restarts_timer():
    activate = read_task("activate.yml")
    rollback = read_task("rollback.yml")
    health = read_task("health.yml")
    assert "ansible.builtin.include_tasks: health.yml" in activate
    assert "ansible.builtin.include_tasks: health.yml" in rollback
    assert rollback.index("Restart services on the restored release") < rollback.index(
        "Verify the restored release before accepting rollback"
    )
    assert "secure-egress-traffic-guard.timer" in rollback
    assert "127.0.0.1" in health
    assert "/healthz" in health


def test_tofu_validate_has_readonly_lock_and_dead_network_environment():
    script = (REPOSITORY_ROOT / "scripts" / "validate-tofu-offline.sh").read_text(encoding="utf-8")
    assert "init -backend=false -input=false -lockfile=readonly" in script
    assert "unset AWS_ACCESS_KEY_ID" in script
    assert "unset AWS_PROFILE" in script
    assert "HTTP_PROXY=http://127.0.0.1:9" in script
    assert script.index("run_safe_tofu init") < script.index("export HTTP_PROXY")
    assert script.index("export HTTP_PROXY") < script.index("run_safe_tofu validate")
