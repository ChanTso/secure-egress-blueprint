from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]


def read(path: str) -> str:
    return (REPOSITORY_ROOT / path).read_text(encoding="utf-8")


def test_network_alarm_uses_the_lightsail_native_resource_contract():
    module = read("infra/tofu/modules/egress-node/main.tf")
    root_variables = read("infra/tofu/variables.tf")
    versions = read("infra/tofu/versions.tf")

    assert '"awscc_lightsail_alarm" "network_out"' in module
    assert "aws_cloudwatch_metric_alarm" not in module
    assert 'metric_name             = "NetworkOut"' in module
    assert "monitored_resource_name = aws_lightsail_instance.this.name" in module
    assert 'notification_triggers   = ["ALARM"]' in module
    assert 'treat_missing_data      = "breaching"' in module
    assert "network_alarm_evaluation_periods" in root_variables
    assert "network_alarm_contact_protocols" in root_variables
    assert "alarm_sns_topic_arn" not in root_variables
    assert 'source  = "hashicorp/awscc"' in versions


def test_alarm_example_remains_default_disabled_and_contact_free():
    example = read("infra/tofu/terraform.tfvars.example")
    assert re.search(r"(?m)^enable_network_alarm\s*=\s*false$", example)
    assert re.search(r"(?m)^network_alarm_contact_protocols\s*=\s*\[\]$", example)
