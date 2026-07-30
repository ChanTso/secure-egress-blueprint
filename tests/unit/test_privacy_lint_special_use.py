from __future__ import annotations

import pytest

from secure_egress.privacy_lint import _safe_ipv4


@pytest.mark.parametrize(
    "value",
    [
        "192.0.0.0/24",
        "192.88.99.0/24",
        "198.18.0.0/15",
        "240.0.0.0/4",
    ],
)
def test_special_use_ipv4_ranges_are_safe_synthetic_fixtures(value: str):
    assert _safe_ipv4(value)
