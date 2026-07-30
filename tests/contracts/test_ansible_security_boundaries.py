from __future__ import annotations

import posixpath
from pathlib import Path

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]
ROLE_ROOT = REPOSITORY_ROOT / "ansible" / "roles" / "secure_egress"
DEFAULTS = yaml.safe_load((ROLE_ROOT / "defaults" / "main.yml").read_text(encoding="utf-8"))
PREFLIGHT_PATH = ROLE_ROOT / "tasks" / "preflight.yml"

PATH_VARIABLES = {
    "secure_egress_root",
    "secure_egress_release_root",
    "secure_egress_current_path",
    "secure_egress_state_root",
    "secure_egress_systemd_root",
    "secure_egress_caddy_binary",
    "secure_egress_xray_binary",
    "secure_egress_traffic_guard_binary",
}


def intended_path_policy(values: dict[str, object]) -> bool:
    if any(type(values.get(name)) is not str for name in PATH_VARIABLES):
        return False
    typed = {name: str(values[name]) for name in PATH_VARIABLES}
    if any(
        not value.startswith("/") or posixpath.normpath(value) != value for value in typed.values()
    ):
        return False

    root = typed["secure_egress_root"]
    releases = typed["secure_egress_release_root"]
    current = typed["secure_egress_current_path"]
    state = typed["secure_egress_state_root"]
    binaries = [
        typed["secure_egress_caddy_binary"],
        typed["secure_egress_xray_binary"],
        typed["secure_egress_traffic_guard_binary"],
    ]
    boundaries = {
        root,
        state,
        typed["secure_egress_systemd_root"],
    }
    return all(
        (
            root != "/",
            state != "/",
            releases.startswith(f"{root}/"),
            current.startswith(f"{root}/"),
            current != releases,
            not current.startswith(f"{releases}/"),
            not releases.startswith(f"{current}/"),
            not state.startswith(f"{root}/"),
            not root.startswith(f"{state}/"),
            typed["secure_egress_systemd_root"] == "/etc/systemd/system",
            not typed["secure_egress_systemd_root"].startswith(f"{root}/"),
            not root.startswith(f"{typed['secure_egress_systemd_root']}/"),
            not typed["secure_egress_systemd_root"].startswith(f"{state}/"),
            not state.startswith(f"{typed['secure_egress_systemd_root']}/"),
            len(set(binaries)) == len(binaries),
            all(
                binary not in boundaries
                and not binary.startswith(f"{root}/")
                and not binary.startswith(f"{state}/")
                for binary in binaries
            ),
            all(
                not binary.startswith(f"{typed['secure_egress_systemd_root']}/")
                for binary in binaries
            ),
            values.get("secure_egress_xray_user") == "xray",
            values.get("secure_egress_xray_group") == "xray",
        )
    )


def test_default_paths_satisfy_the_intended_policy():
    assert intended_path_policy(DEFAULTS)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("secure_egress_root", "relative"),
        ("secure_egress_root", "/"),
        ("secure_egress_root", "/etc"),
        ("secure_egress_release_root", "/opt/secure-egress/releases/../escape"),
        ("secure_egress_current_path", "/opt/secure-egress/releases/current"),
        ("secure_egress_state_root", "/opt/secure-egress/state"),
        ("secure_egress_state_root", "/var/lib/secure-egress/../escape"),
        ("secure_egress_systemd_root", "/var/lib/synthetic-systemd"),
        ("secure_egress_xray_binary", "/opt/secure-egress/bin/xray"),
        ("secure_egress_xray_binary", "/usr/local/bin/../bin/xray"),
        ("secure_egress_xray_binary", "/usr/bin/caddy"),
        ("secure_egress_xray_binary", "/etc/systemd/system/xray"),
        ("secure_egress_xray_user", "root"),
        ("secure_egress_xray_group", "root"),
    ],
)
def test_intended_path_policy_rejects_escape_overlap_and_aliases(name, value):
    values = dict(DEFAULTS)
    values[name] = value
    assert not intended_path_policy(values)


def test_preflight_applies_normpath_to_every_controlled_path():
    text = PREFLIGHT_PATH.read_text(encoding="utf-8")
    for variable in PATH_VARIABLES:
        assert f"{variable} | ansible.builtin.normpath" in text
    assert "secure_egress_systemd_root == '/etc/systemd/system'" in text
    assert "secure_egress_xray_user == 'xray'" in text
    assert "secure_egress_xray_group == 'xray'" in text


def test_preflight_checks_xray_binary_before_running_it_as_xray():
    tasks = yaml.safe_load(PREFLIGHT_PATH.read_text(encoding="utf-8"))
    names = [task["name"] for task in tasks]
    stat_index = names.index("Inspect the Xray executable before invoking it")
    assert_index = names.index("Require a root-owned non-writable regular Xray executable")
    version_index = names.index("Confirm Xray is installed locally on the managed node")
    assert stat_index < assert_index < version_index

    stat_task = tasks[stat_index]["ansible.builtin.stat"]
    assert stat_task["follow"] is False
    assertions = "\n".join(tasks[assert_index]["ansible.builtin.assert"]["that"])
    assert ".stat.isreg" in assertions
    assert ".stat.uid" in assertions
    assert "^0[57][0145][15]$" in assertions
    assert tasks[version_index]["become_user"] == "{{ secure_egress_xray_user }}"
