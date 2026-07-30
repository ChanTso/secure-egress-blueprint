from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parents[2]
VARIABLES = REPOSITORY_ROOT / "infra" / "tofu" / "variables.tf"


def variable_block(name: str) -> str:
    text = VARIABLES.read_text(encoding="utf-8")
    start = text.index(f'variable "{name}"')
    next_variable = text.find('\nvariable "', start + 1)
    return text[start:] if next_variable == -1 else text[start:next_variable]


def intended_cidr_policy(value: str) -> bool:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False
    return network.version == 4 and network.prefixlen > 0


@pytest.mark.parametrize(
    "value",
    [
        "192.0.2.7/0",
        "192.0.2.7/24",
        "198.51.100.129/25",
        "203.0.113.9/0",
    ],
)
def test_synthetic_host_bit_and_zero_prefix_counterexamples_are_rejected(value):
    assert intended_cidr_policy(value) is False


@pytest.mark.parametrize(
    "value",
    [
        "192.0.2.0/24",
        "198.51.100.128/25",
        "203.0.113.9/32",
    ],
)
def test_synthetic_canonical_nonzero_prefixes_are_allowed(value):
    assert intended_cidr_policy(value) is True


@pytest.mark.parametrize("variable", ["tls_source_cidrs", "ssh_source_cidrs"])
def test_tofu_implements_prefix_and_canonical_network_checks(variable):
    block = variable_block(variable)
    assert re.search(r'tonumber\(split\("/", cidr\)\[1\]\) > 0', block)
    assert 'split("/", cidr)[0] == cidrhost(cidr, 0)' in block
    assert "can(cidrnetmask(cidr))" in block
    assert "try(" in block
