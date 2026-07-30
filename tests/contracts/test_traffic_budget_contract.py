from __future__ import annotations

import json
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]


def test_traffic_budget_namespace_includes_both_directions():
    defaults = yaml.safe_load(
        (
            REPOSITORY_ROOT / "ansible" / "roles" / "secure_egress" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
    )
    fixture = json.loads(
        (REPOSITORY_ROOT / "examples" / "traffic-guard.synthetic.json").read_text(encoding="utf-8")
    )
    expected = "inbound>>>tunnel>>>traffic>>>"
    assert defaults["secure_egress_traffic_guard_counter_prefix"] == expected
    assert fixture["counter_prefix"] == expected
