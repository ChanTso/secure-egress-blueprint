"""Deterministic traffic-budget decisions with an explicit stop interlock."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import posixpath
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

AUTO_STOP_ACKNOWLEDGEMENT = "ALLOW_SYNTHETIC_AUTO_STOP"
XRAY_SERVICE = "secure-egress-xray.service"
XRAY_QUERY_USER = "xray"
MANAGED_EGRESS_UNITS = (
    "secure-egress-caddy.service",
    XRAY_SERVICE,
    "secure-egress-traffic-guard.timer",
)

_CONFIG_KEYS = frozenset(
    {
        "limit_bytes",
        "warning_ratio",
        "auto_stop_enabled",
        "stop_acknowledgement",
        "xray_binary",
        "stats_endpoint",
        "counter_prefix",
        "state_path",
        "service_name",
        "query_user",
    }
)
_STATE_KEYS = frozenset({"period", "accumulated_bytes", "last_counter_bytes"})
_PERIOD_PATTERN = re.compile(r"(?:[1-9]\d{3})-(?:0[1-9]|1[0-2])\Z")
_COUNTER_PREFIX_PATTERN = re.compile(r"(?:[A-Za-z0-9][A-Za-z0-9_.:-]*>>>)+\Z")


class Action(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    STOP = "stop"
    NO_DATA = "no-data"


@dataclass(frozen=True)
class BudgetPolicy:
    limit_bytes: int
    warning_ratio: float
    auto_stop_enabled: bool
    stop_acknowledgement: str

    def validate(self) -> None:
        if type(self.limit_bytes) is not int or self.limit_bytes <= 0:
            raise ValueError("limit_bytes must be a positive integer")
        if (
            type(self.warning_ratio) not in {int, float}
            or not math.isfinite(self.warning_ratio)
            or not 0 < self.warning_ratio < 1
        ):
            raise ValueError("warning_ratio must be a finite number between zero and one")
        if type(self.auto_stop_enabled) is not bool:
            raise ValueError("auto_stop_enabled must be a boolean")
        if type(self.stop_acknowledgement) is not str:
            raise ValueError("stop_acknowledgement must be a string")
        if self.auto_stop_enabled and self.stop_acknowledgement != AUTO_STOP_ACKNOWLEDGEMENT:
            raise ValueError("auto-stop requires the explicit acknowledgement")


@dataclass(frozen=True)
class TrafficState:
    period: str
    accumulated_bytes: int
    last_counter_bytes: int

    def validate(self) -> None:
        if type(self.period) is not str or not _PERIOD_PATTERN.fullmatch(self.period):
            raise ValueError("state period must use a valid YYYY-MM value")
        for name, value in (
            ("accumulated_bytes", self.accumulated_bytes),
            ("last_counter_bytes", self.last_counter_bytes),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"state {name} must be a non-negative integer")


@dataclass(frozen=True)
class Decision:
    action: Action
    accumulated_bytes: int
    limit_bytes: int
    reason: str


def billing_period(timestamp: datetime) -> str:
    """Return a stable UTC monthly bucket."""
    return timestamp.astimezone(UTC).strftime("%Y-%m")


def update_state(
    previous: TrafficState | None,
    observed_counter_bytes: int,
    observed_at: datetime,
) -> TrafficState:
    """Accumulate a monotonic counter, including reset and month rollover handling."""
    if type(observed_counter_bytes) is not int or observed_counter_bytes < 0:
        raise ValueError("observed counter must be a non-negative integer")
    if previous is not None:
        previous.validate()

    period = billing_period(observed_at)
    if previous is None:
        return TrafficState(period, observed_counter_bytes, observed_counter_bytes)
    if previous.period != period:
        # Establish a new-period baseline rather than charging the new period
        # for a process counter that includes earlier months.
        return TrafficState(period, 0, observed_counter_bytes)

    delta = (
        observed_counter_bytes - previous.last_counter_bytes
        if observed_counter_bytes >= previous.last_counter_bytes
        else observed_counter_bytes
    )
    return TrafficState(
        period=period,
        accumulated_bytes=previous.accumulated_bytes + delta,
        last_counter_bytes=observed_counter_bytes,
    )


def decide(policy: BudgetPolicy, state: TrafficState | None) -> Decision:
    """Map state to a side-effect-free budget action."""
    policy.validate()
    if state is None:
        return Decision(Action.NO_DATA, 0, policy.limit_bytes, "fresh metrics are unavailable")
    state.validate()
    if state.accumulated_bytes >= policy.limit_bytes:
        action = Action.STOP if policy.auto_stop_enabled else Action.WARN
        reason = (
            "limit reached; auto-stop armed" if action is Action.STOP else "limit reached; dry-run"
        )
        return Decision(action, state.accumulated_bytes, policy.limit_bytes, reason)
    if state.accumulated_bytes >= int(policy.limit_bytes * policy.warning_ratio):
        return Decision(
            Action.WARN,
            state.accumulated_bytes,
            policy.limit_bytes,
            "warning threshold",
        )
    return Decision(Action.ALLOW, state.accumulated_bytes, policy.limit_bytes, "within budget")


def _validate_counter_prefix(counter_prefix: object) -> str:
    if (
        type(counter_prefix) is not str
        or not counter_prefix
        or not _COUNTER_PREFIX_PATTERN.fullmatch(counter_prefix)
    ):
        raise ValueError("counter_prefix must be a non-empty Xray stat namespace prefix")
    return counter_prefix


def parse_xray_stats(payload: str, counter_prefix: str) -> int:
    """Sum integer Xray stat values below one configured namespace."""
    prefix = _validate_counter_prefix(counter_prefix)
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise TypeError("Xray stats response must be an object")
    stats = document.get("stat")
    if not isinstance(stats, list):
        raise TypeError("Xray stats response does not contain a stat list")

    total = 0
    matched = False
    for item in stats:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        value = item.get("value")
        if isinstance(name, str) and name.startswith(prefix):
            if type(value) is not int or value < 0:
                raise ValueError("Xray stat values must be non-negative integers")
            total += value
            matched = True
    if not matched:
        raise ValueError("no Xray counters matched the configured prefix")
    return total


def _validate_state_document(data: object) -> TrafficState:
    if not isinstance(data, dict):
        raise TypeError("traffic state must be a JSON object")
    keys = set(data)
    missing = sorted(_STATE_KEYS - keys)
    unknown = sorted(keys - _STATE_KEYS)
    if missing:
        raise ValueError(f"traffic state is missing keys: {', '.join(missing)}")
    if unknown:
        raise ValueError(f"traffic state contains unknown keys: {', '.join(unknown)}")
    state = TrafficState(
        period=data["period"],
        accumulated_bytes=data["accumulated_bytes"],
        last_counter_bytes=data["last_counter_bytes"],
    )
    state.validate()
    return state


def load_state(path: Path) -> TrafficState | None:
    if not path.exists():
        return None
    return _validate_state_document(json.loads(path.read_text(encoding="utf-8")))


def write_state(path: Path, state: TrafficState) -> None:
    """Atomically persist state without making it group/world readable."""
    state.validate()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".traffic-state-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(asdict(state), handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _validate_stats_endpoint(endpoint: object) -> str:
    if type(endpoint) is not str or not endpoint:
        raise ValueError("stats_endpoint must be a loopback IP and port")
    if endpoint.startswith("["):
        closing = endpoint.find("]")
        if closing < 0 or endpoint[closing + 1 : closing + 2] != ":":
            raise ValueError("stats_endpoint must be a loopback IP and port")
        host = endpoint[1:closing]
        port_text = endpoint[closing + 2 :]
    else:
        if endpoint.count(":") != 1:
            raise ValueError("stats_endpoint must be a loopback IP and port")
        host, port_text = endpoint.rsplit(":", 1)
    try:
        address = ipaddress.ip_address(host)
        port = int(port_text)
    except ValueError as error:
        raise ValueError("stats_endpoint must be a loopback IP and port") from error
    if not address.is_loopback or not port_text.isascii() or not port_text.isdecimal():
        raise ValueError("stats_endpoint must be a loopback IP and port")
    if not 1 <= port <= 65535:
        raise ValueError("stats_endpoint port must be between 1 and 65535")
    return endpoint


def _validate_state_path(value: object) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("state_path must be an absolute normalized path")
    if (
        not value.startswith("/")
        or value.startswith("//")
        or value == "/"
        or posixpath.normpath(value) != value
    ):
        raise ValueError("state_path must be an absolute normalized path")
    return value


def _validate_config(data: object) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise TypeError("traffic guard config must be a JSON object")
    keys = set(data)
    missing = sorted(_CONFIG_KEYS - keys)
    unknown = sorted(keys - _CONFIG_KEYS)
    if missing:
        raise ValueError(f"traffic guard config is missing keys: {', '.join(missing)}")
    if unknown:
        raise ValueError(f"traffic guard config contains unknown keys: {', '.join(unknown)}")

    policy = BudgetPolicy(
        limit_bytes=data["limit_bytes"],
        warning_ratio=data["warning_ratio"],
        auto_stop_enabled=data["auto_stop_enabled"],
        stop_acknowledgement=data["stop_acknowledgement"],
    )
    policy.validate()

    xray_binary = data["xray_binary"]
    if type(xray_binary) is not str or not Path(xray_binary).is_absolute():
        raise ValueError("xray_binary must be an absolute path")
    _validate_stats_endpoint(data["stats_endpoint"])
    _validate_counter_prefix(data["counter_prefix"])
    _validate_state_path(data["state_path"])
    if type(data["service_name"]) is not str or data["service_name"] != XRAY_SERVICE:
        raise ValueError(f"service_name must be {XRAY_SERVICE}")
    if type(data["query_user"]) is not str or data["query_user"] != XRAY_QUERY_USER:
        raise ValueError(f"query_user must be {XRAY_QUERY_USER}")
    return dict(data)


def query_xray(
    xray_binary: str,
    endpoint: str,
    query_user: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    binary = Path(xray_binary)
    if not binary.is_absolute():
        raise ValueError("xray_binary must be an absolute path")
    server = _validate_stats_endpoint(endpoint)
    if type(query_user) is not str or query_user != XRAY_QUERY_USER:
        raise ValueError(f"query_user must be {XRAY_QUERY_USER}")
    result = runner(
        [
            str(binary),
            "api",
            "statsquery",
            f"--server={server}",
            "--reset=false",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        user=query_user,
        group=query_user,
        extra_groups=(),
        umask=0o077,
    )
    return result.stdout


def disable_managed_egress(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Persistently stop the fixed, repository-owned egress unit set."""
    runner(
        ["/usr/bin/systemctl", "disable", "--now", *MANAGED_EGRESS_UNITS],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def load_config(path: Path) -> dict[str, Any]:
    return _validate_config(json.loads(path.read_text(encoding="utf-8")))


def run_once(
    config: Mapping[str, Any],
    *,
    enforce: bool,
    now: datetime | None = None,
) -> Decision:
    validated = _validate_config(config)
    policy = BudgetPolicy(
        limit_bytes=validated["limit_bytes"],
        warning_ratio=validated["warning_ratio"],
        auto_stop_enabled=validated["auto_stop_enabled"],
        stop_acknowledgement=validated["stop_acknowledgement"],
    )
    state_path = Path(validated["state_path"])
    payload = query_xray(
        validated["xray_binary"],
        validated["stats_endpoint"],
        validated["query_user"],
    )
    observed = parse_xray_stats(payload, validated["counter_prefix"])
    state = update_state(load_state(state_path), observed, now or datetime.now(UTC))
    write_state(state_path, state)
    result = decide(policy, state)
    if result.action is Action.STOP and enforce:
        disable_managed_egress()
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="persistently stop the fixed managed egress units on a stop decision or error",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_once(load_config(args.config), enforce=args.enforce)
    except (
        OSError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
        UnicodeError,
    ) as error:
        if args.enforce:
            try:
                disable_managed_egress()
            except (OSError, subprocess.SubprocessError):
                print("traffic guard fail-safe shutdown failed", file=sys.stderr)
                return 2
            print(f"traffic guard failed closed: {type(error).__name__}", file=sys.stderr)
            return 42
        print(f"traffic guard did not act: {type(error).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), sort_keys=True))
    return 42 if result.action is Action.STOP and args.enforce else 0


if __name__ == "__main__":
    raise SystemExit(main())
