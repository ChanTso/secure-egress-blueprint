from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import secure_egress.privacy_lint as privacy_lint
from secure_egress.privacy_lint import Finding, scan_repository, scan_text


def finding_rules(text: str) -> set[str]:
    return {finding.rule for finding in scan_text(Path("synthetic.txt"), text)}


def test_safe_documentation_values_pass():
    text = "\n".join(
        [
            "egress.example.com",
            "maintainer@example.org",
            "192.0.2.10",
            "198.51.100.0/24",
            "203.0.113.9",
            "127.0.0.1",
            "00000000-0000-4000-8000-000000000001",
            "arn:aws:sns:us-east-2:123456789012:synthetic-alerts",
            "https://github.com/example/project",
        ]
    )
    assert scan_text(Path("synthetic.txt"), text) == []


def test_each_sensitive_pattern_is_reported_without_embedding_private_fixtures():
    non_public_domain = "private" + "." + "dev"
    non_public_email = "operator@" + non_public_domain
    non_documentation_ip = "8.8." + "8.8"
    non_synthetic_uuid = "-".join(["11111111", "1111", "4111", "8111", "111111" + "111111"])
    non_synthetic_account = "999999" + "999999"
    access_key = "AKIA" + ("A" * 16)
    private_path = "/Users/" + "synthetic-private/"
    unsafe_command = "tofu" + " apply"
    text = "\n".join(
        [
            non_public_domain,
            non_public_email,
            non_documentation_ip,
            non_synthetic_uuid,
            non_synthetic_account,
            access_key,
            private_path,
            unsafe_command,
        ]
    )
    assert finding_rules(text) == {
        "cloud-mutation-command",
        "non-allowlisted-domain",
        "non-documentation-ipv4",
        "non-synthetic-account",
        "non-synthetic-email",
        "non-synthetic-uuid",
        "private-absolute-path",
        "secret-pattern",
    }


def test_tracked_files_uses_null_delimited_git_output(monkeypatch, tmp_path):
    monkeypatch.setattr(
        privacy_lint.subprocess,
        "check_output",
        lambda *args, **kwargs: b"one.txt\0nested/two.json\0",
    )
    assert list(privacy_lint.tracked_or_local_files(tmp_path)) == [
        tmp_path / "one.txt",
        tmp_path / "nested/two.json",
    ]


def test_tracked_files_falls_back_to_walk_and_honors_exclusions(monkeypatch, tmp_path):
    def fail_git(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "git")

    monkeypatch.setattr(privacy_lint.subprocess, "check_output", fail_git)
    kept = tmp_path / "kept.txt"
    kept.write_text("synthetic", encoding="utf-8")
    excluded = tmp_path / ".venv" / "ignored.txt"
    excluded.parent.mkdir()
    excluded.write_text("ignored", encoding="utf-8")

    assert list(privacy_lint.tracked_or_local_files(tmp_path)) == [kept]


def test_tracked_files_falls_back_when_git_is_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(
        privacy_lint.subprocess,
        "check_output",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("missing")),
    )
    path = tmp_path / "fixture.json"
    path.write_text("{}\n", encoding="utf-8")
    assert list(privacy_lint.tracked_or_local_files(tmp_path)) == [path]


def test_scan_repository_rejects_unapproved_file_type_and_binary_text(monkeypatch, tmp_path):
    safe = tmp_path / "safe.json"
    safe.write_text('{"domain": "egress.example.com"}\n', encoding="utf-8")
    ignored = tmp_path / "image.png"
    ignored.write_bytes(b"not-inspected")
    binary = tmp_path / "broken.txt"
    binary.write_bytes(b"\xff")
    missing = tmp_path / "missing.txt"
    monkeypatch.setattr(
        privacy_lint,
        "tracked_or_local_files",
        lambda root: iter([safe, ignored, binary, missing]),
    )
    assert scan_repository(tmp_path) == [
        Finding(Path("image.png"), 1, "unapproved-file-type"),
        Finding(Path("broken.txt"), 1, "unexpected-binary"),
    ]


def test_scan_repository_reports_text_findings(monkeypatch, tmp_path):
    path = tmp_path / "unsafe.txt"
    path.write_text("tofu apply\n", encoding="utf-8")
    monkeypatch.setattr(
        privacy_lint,
        "tracked_or_local_files",
        lambda root: iter([path]),
    )
    assert scan_repository(tmp_path) == [Finding(Path("unsafe.txt"), 1, "cloud-mutation-command")]


def test_main_reports_findings_without_echoing_values(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(
        privacy_lint,
        "scan_repository",
        lambda root: [Finding(Path("fixture.txt"), 7, "secret-pattern")],
    )
    assert privacy_lint.main([str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "fixture.txt:7: secret-pattern" in captured.err
    assert "1 finding" in captured.err


def test_main_reports_success(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(privacy_lint, "scan_repository", lambda root: [])
    assert privacy_lint.main([str(tmp_path)]) == 0
    assert capsys.readouterr().out == "privacy lint passed\n"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", True),
        ("sub.example.net.", True),
        ("githubusercontent.com", True),
        ("private" + "." + "dev", False),
    ],
)
def test_safe_domain_policy(value, expected):
    assert privacy_lint._safe_domain(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.0.2.1", True),
        ("203.0.113.0/24", True),
        ("127.0.0.1", True),
        ("8.8." + "8.8", False),
    ],
)
def test_safe_ipv4_policy(value, expected):
    assert privacy_lint._safe_ipv4(value) is expected
