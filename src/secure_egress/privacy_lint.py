"""Reject non-synthetic identifiers and unsafe operational shortcuts."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".conf",
    ".css",
    ".html",
    ".hcl",
    ".j2",
    ".js",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".tf",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
EXCLUDED_PARTS = {".git", ".terraform", ".venv", "__pycache__", "dist", "htmlcov"}
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:ai|app|au|aws|ca|cloud|co|com|de|dev|fr|info|io|jp|me|net|online|org|"
    r"security|site|tech|uk|us|xyz)(?![A-Za-z0-9_-])",
    re.I,
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,63})\b", re.I)
IPV4_RE = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?:/\d{1,2})?(?![\d.])"
)
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.I,
)
ACCOUNT_RE = re.compile(r"(?<![A-Za-z0-9])\d{12}(?![A-Za-z0-9])")
SECRET_RE = re.compile(
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})|"
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
)
ABSOLUTE_USER_PATH_RE = re.compile(r"(?:/Users/|/home/)[A-Za-z0-9._-]+/")
UNSAFE_COMMAND_RE = re.compile(
    r"(?m)^\s*(?:\$ )?(?:tofu|terraform)\s+(?:apply|destroy|import)\b|"
    r"^\s*(?:\$ )?aws\s+(?:cloudfront|cloudwatch|ec2|iam|lightsail|route53|s3|"
    r"sts|wafv2)\b"
)

SAFE_DOMAIN_SUFFIXES = {
    "example.com",
    "example.net",
    "example.org",
    "docs.aws.amazon.com",
    "github.com",
    "githubusercontent.com",
    "registry.opentofu.org",
    "shields.io",
    "apache.org",
}
SAFE_UUIDS = {
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
}
SAFE_ACCOUNTS = {"123456789012"}
SAFE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    rule: str


def _safe_domain(domain: str) -> bool:
    candidate = domain.rstrip(".").casefold()
    return any(
        candidate == suffix or candidate.endswith("." + suffix) for suffix in SAFE_DOMAIN_SUFFIXES
    )


def _safe_ipv4(value: str) -> bool:
    address_text = value.split("/", maxsplit=1)[0]
    address = ipaddress.ip_address(address_text)
    return any(address in network for network in SAFE_NETWORKS)


def _walk_local_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and not any(part in EXCLUDED_PARTS for part in path.parts):
            yield path


def tracked_or_local_files(root: Path) -> Iterable[Path]:
    try:
        raw = subprocess.check_output(
            ["/usr/bin/git", "-C", str(root), "ls-files", "-z"],
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        yield from _walk_local_files(root)
        return
    tracked = [item for item in raw.split(b"\0") if item]
    if not tracked:
        yield from _walk_local_files(root)
        return
    for item in tracked:
        yield root / os.fsdecode(item)


def scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        uuid_matches = list(UUID_RE.finditer(line))
        if SECRET_RE.search(line):
            findings.append(Finding(path, line_number, "secret-pattern"))
        if ABSOLUTE_USER_PATH_RE.search(line):
            findings.append(Finding(path, line_number, "private-absolute-path"))
        if UNSAFE_COMMAND_RE.search(line):
            findings.append(Finding(path, line_number, "cloud-mutation-command"))
        for match in EMAIL_RE.finditer(line):
            if not _safe_domain(match.group(1)):
                findings.append(Finding(path, line_number, "non-synthetic-email"))
        for match in DOMAIN_RE.finditer(line):
            if not _safe_domain(match.group(0)):
                findings.append(Finding(path, line_number, "non-allowlisted-domain"))
        for match in IPV4_RE.finditer(line):
            if not _safe_ipv4(match.group(0)):
                findings.append(Finding(path, line_number, "non-documentation-ipv4"))
        for match in uuid_matches:
            if match.group(0).casefold() not in SAFE_UUIDS:
                findings.append(Finding(path, line_number, "non-synthetic-uuid"))
        for match in ACCOUNT_RE.finditer(line):
            if any(
                uuid.start() <= match.start() and match.end() <= uuid.end() for uuid in uuid_matches
            ):
                continue
            if match.group(0) not in SAFE_ACCOUNTS:
                findings.append(Finding(path, line_number, "non-synthetic-account"))
    return findings


def scan_repository(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in tracked_or_local_files(root):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        is_text = path.suffix.casefold() in TEXT_SUFFIXES or path.name.casefold().endswith(
            ".tfvars.example"
        )
        if not is_text:
            findings.append(Finding(relative, 1, "unapproved-file-type"))
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(Finding(relative, 1, "unexpected-binary"))
            continue
        findings.extend(scan_text(relative, text))
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    root = build_parser().parse_args(argv).root.resolve()
    findings = scan_repository(root)
    for finding in findings:
        print(f"{finding.path}:{finding.line}: {finding.rule}", file=sys.stderr)
    if findings:
        print(f"privacy lint failed with {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("privacy lint passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
