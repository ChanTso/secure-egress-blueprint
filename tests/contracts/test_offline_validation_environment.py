from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]


def test_tofu_validation_cannot_load_shared_or_container_credentials():
    script = (REPOSITORY_ROOT / "scripts" / "validate-tofu-offline.sh").read_text(encoding="utf-8")
    assert "AWS_CONFIG_FILE=/dev/null" in script
    assert "AWS_SHARED_CREDENTIALS_FILE=/dev/null" in script
    assert "unset AWS_WEB_IDENTITY_TOKEN_FILE" in script
    assert "unset AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" in script
    assert script.index("run_safe_tofu init") < script.index("AWS_CONFIG_FILE=/dev/null")
    assert script.index("AWS_CONFIG_FILE=/dev/null") < script.index("run_safe_tofu validate")
