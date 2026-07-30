from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime, timedelta, timezone

import pytest

from secure_egress import traffic_guard
from secure_egress.traffic_guard import (
    AUTO_STOP_ACKNOWLEDGEMENT,
    MANAGED_EGRESS_UNITS,
    XRAY_QUERY_USER,
    XRAY_SERVICE,
    Action,
    BudgetPolicy,
    Decision,
    TrafficState,
    billing_period,
    decide,
    disable_managed_egress,
    load_config,
    load_state,
    parse_xray_stats,
    query_xray,
    run_once,
    update_state,
    write_state,
)


def valid_policy(**overrides: object) -> BudgetPolicy:
    values = {
        "limit_bytes": 1000,
        "warning_ratio": 0.8,
        "auto_stop_enabled": False,
        "stop_acknowledgement": "",
    }
    values.update(overrides)
    return BudgetPolicy(**values)


def valid_config(tmp_path, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "limit_bytes": 1000,
        "warning_ratio": 0.8,
        "auto_stop_enabled": False,
        "stop_acknowledgement": "",
        "xray_binary": "/usr/local/bin/xray",
        "stats_endpoint": "127.0.0.1:11085",
        "counter_prefix": "inbound>>>tunnel>>>traffic>>>",
        "state_path": str(tmp_path / "state.json"),
        "service_name": XRAY_SERVICE,
        "query_user": XRAY_QUERY_USER,
    }
    values.update(overrides)
    return values


@pytest.mark.parametrize(
    ("policy", "message"),
    [
        (valid_policy(limit_bytes=0), "limit_bytes"),
        (valid_policy(limit_bytes=True), "limit_bytes"),
        (valid_policy(warning_ratio=0), "warning_ratio"),
        (valid_policy(warning_ratio=1), "warning_ratio"),
        (valid_policy(warning_ratio=float("nan")), "warning_ratio"),
        (valid_policy(auto_stop_enabled=1), "auto_stop_enabled"),
        (valid_policy(stop_acknowledgement=None), "stop_acknowledgement"),
        (valid_policy(auto_stop_enabled=True), "explicit acknowledgement"),
    ],
)
def test_policy_validation_rejects_unsafe_values(policy, message):
    with pytest.raises(ValueError, match=message):
        policy.validate()


def test_policy_validation_accepts_armed_auto_stop():
    valid_policy(
        auto_stop_enabled=True,
        stop_acknowledgement=AUTO_STOP_ACKNOWLEDGEMENT,
    ).validate()


def test_billing_period_normalizes_to_utc():
    offset = timezone(timedelta(hours=10))
    assert billing_period(datetime(2026, 2, 1, 1, tzinfo=offset)) == "2026-01"


def test_update_state_initializes_and_rolls_over_month():
    observed_at = datetime(2026, 2, 1, tzinfo=UTC)
    assert update_state(None, 12, observed_at) == TrafficState("2026-02", 12, 12)
    previous = TrafficState("2026-01", 900, 700)
    assert update_state(previous, 10, observed_at) == TrafficState("2026-02", 0, 10)


def test_update_state_accumulates_monotonic_and_reset_counters():
    observed_at = datetime(2026, 2, 1, tzinfo=UTC)
    previous = TrafficState("2026-02", 100, 50)
    assert update_state(previous, 75, observed_at) == TrafficState("2026-02", 125, 75)
    assert update_state(previous, 20, observed_at) == TrafficState("2026-02", 120, 20)


@pytest.mark.parametrize("value", [-1, True, 1.5])
def test_update_state_rejects_invalid_counters(value):
    with pytest.raises(ValueError, match="non-negative integer"):
        update_state(None, value, datetime.now(UTC))


def test_update_state_rejects_invalid_previous_state():
    with pytest.raises(ValueError, match="YYYY-MM"):
        update_state(TrafficState("not-a-period", 0, 0), 1, datetime.now(UTC))


@pytest.mark.parametrize(
    ("state", "action", "reason"),
    [
        (None, Action.NO_DATA, "fresh metrics are unavailable"),
        (TrafficState("2026-01", 100, 100), Action.ALLOW, "within budget"),
        (TrafficState("2026-01", 800, 800), Action.WARN, "warning threshold"),
        (TrafficState("2026-01", 1000, 1000), Action.WARN, "limit reached; dry-run"),
    ],
)
def test_decide_is_side_effect_free_by_default(state, action, reason):
    decision = decide(valid_policy(), state)
    assert decision.action is action
    assert decision.reason == reason
    assert decision.limit_bytes == 1000


def test_decide_returns_stop_only_when_policy_is_armed():
    policy = valid_policy(
        auto_stop_enabled=True,
        stop_acknowledgement=AUTO_STOP_ACKNOWLEDGEMENT,
    )
    decision = decide(policy, TrafficState("2026-01", 1000, 1000))
    assert decision == Decision(Action.STOP, 1000, 1000, "limit reached; auto-stop armed")


def test_decide_validates_policy_and_state_first():
    with pytest.raises(ValueError, match="positive"):
        decide(valid_policy(limit_bytes=-1), None)
    with pytest.raises(ValueError, match="non-negative"):
        decide(valid_policy(), TrafficState("2026-01", -1, 0))


def test_parse_xray_stats_sums_matching_non_negative_values():
    payload = json.dumps(
        {
            "stat": [
                {"name": "inbound>>>tunnel>>>traffic>>>uplink", "value": 10},
                {"name": "inbound>>>tunnel>>>traffic>>>downlink", "value": 15},
                {"name": "outbound>>>egress", "value": 99},
                "invalid",
            ]
        }
    )
    assert parse_xray_stats(payload, "inbound>>>tunnel>>>traffic>>>") == 25


@pytest.mark.parametrize(
    ("payload", "prefix", "message"),
    [
        ("[]", "inbound>>>", "must be an object"),
        ("{}", "inbound>>>", "stat list"),
        ('{"stat": []}', "inbound>>>", "no Xray counters"),
        (
            '{"stat": [{"name": "inbound>>>tunnel", "value": -1}]}',
            "inbound>>>",
            "non-negative integers",
        ),
        (
            '{"stat": [{"name": "inbound>>>tunnel", "value": true}]}',
            "inbound>>>",
            "non-negative integers",
        ),
        ('{"stat": []}', "", "non-empty"),
        ('{"stat": []}', "inbound", "non-empty"),
        ('{"stat": []}', "inbound>>>>>>", "non-empty"),
    ],
)
def test_parse_xray_stats_rejects_invalid_payloads_and_prefixes(payload, prefix, message):
    with pytest.raises((TypeError, ValueError), match=message):
        parse_xray_stats(payload, prefix)


def test_state_round_trip_is_atomic_private_and_strict(tmp_path):
    path = tmp_path / "nested" / "state.json"
    state = TrafficState("2026-02", 123, 100)
    assert load_state(path) is None
    write_state(path, state)
    assert load_state(path) == state
    assert os.stat(path).st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "JSON object"),
        (
            {"period": "2026-02", "accumulated_bytes": 1},
            "missing keys",
        ),
        (
            {
                "period": "2026-02",
                "accumulated_bytes": 1,
                "last_counter_bytes": 1,
                "extra": 1,
            },
            "unknown keys",
        ),
        (
            {"period": "2026-2", "accumulated_bytes": 1, "last_counter_bytes": 1},
            "YYYY-MM",
        ),
        (
            {"period": "0000-01", "accumulated_bytes": 1, "last_counter_bytes": 1},
            "YYYY-MM",
        ),
        (
            {"period": "2026-13", "accumulated_bytes": 1, "last_counter_bytes": 1},
            "YYYY-MM",
        ),
        (
            {"period": 202602, "accumulated_bytes": 1, "last_counter_bytes": 1},
            "YYYY-MM",
        ),
        (
            {"period": "2026-02", "accumulated_bytes": "1", "last_counter_bytes": 1},
            "non-negative integer",
        ),
        (
            {"period": "2026-02", "accumulated_bytes": 1, "last_counter_bytes": True},
            "non-negative integer",
        ),
        (
            {"period": "2026-02", "accumulated_bytes": -1, "last_counter_bytes": 1},
            "non-negative integer",
        ),
    ],
)
def test_load_state_rejects_noncanonical_or_unsafe_documents(tmp_path, document, message):
    path = tmp_path / "state.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises((TypeError, ValueError), match=message):
        load_state(path)


def test_write_state_rejects_invalid_in_memory_state(tmp_path):
    with pytest.raises(ValueError, match="non-negative"):
        write_state(tmp_path / "state.json", TrafficState("2026-02", -1, 0))


def test_query_xray_invokes_only_the_loopback_stats_api():
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout='{"stat": []}\n', stderr="")

    assert (
        query_xray(
            "/usr/local/bin/xray",
            "127.0.0.1:11085",
            XRAY_QUERY_USER,
            runner,
        )
        == '{"stat": []}\n'
    )
    assert calls[0][0] == [
        "/usr/local/bin/xray",
        "api",
        "statsquery",
        "--server=127.0.0.1:11085",
        "--reset=false",
    ]
    assert calls[0][1]["timeout"] == 10
    assert calls[0][1]["user"] == XRAY_QUERY_USER
    assert calls[0][1]["group"] == XRAY_QUERY_USER
    assert calls[0][1]["extra_groups"] == ()
    assert calls[0][1]["umask"] == 0o077


@pytest.mark.parametrize(
    "endpoint",
    [
        "localhost:11085",
        "192.0.2.1:11085",
        "127.0.0.1",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "::1:11085",
    ],
)
def test_query_xray_rejects_non_loopback_or_malformed_endpoints(endpoint):
    with pytest.raises(ValueError, match=r"loopback|port"):
        query_xray(
            "/usr/local/bin/xray",
            endpoint,
            XRAY_QUERY_USER,
            lambda *_args, **_kwargs: None,
        )


def test_query_xray_rejects_any_other_or_root_query_identity():
    for query_user in ("root", "synthetic-user", "", 1):
        with pytest.raises(ValueError, match="query_user"):
            query_xray(
                "/usr/local/bin/xray",
                "127.0.0.1:11085",
                query_user,  # type: ignore[arg-type]
                lambda *_args, **_kwargs: None,
            )


def test_query_xray_accepts_bracketed_ipv6_loopback():
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="{}", stderr="")

    query_xray("/usr/local/bin/xray", "[::1]:11085", XRAY_QUERY_USER, runner)
    assert "--server=[::1]:11085" in calls[0][0]


def test_disable_managed_egress_uses_one_fixed_persistent_command():
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    disable_managed_egress(runner)
    assert calls == [
        (
            [
                "/usr/bin/systemctl",
                "disable",
                "--now",
                *MANAGED_EGRESS_UNITS,
            ],
            {
                "check": True,
                "capture_output": True,
                "text": True,
                "timeout": 30,
            },
        )
    ]
    assert MANAGED_EGRESS_UNITS == (
        "secure-egress-caddy.service",
        "secure-egress-xray.service",
        "secure-egress-traffic-guard.timer",
    )


def test_load_config_requires_an_exact_object_schema(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(TypeError, match="JSON object"):
        load_config(path)

    path.write_text('{"limit_bytes": 1}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="missing keys"):
        load_config(path)

    config = valid_config(tmp_path)
    config["unexpected"] = True
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown keys"):
        load_config(path)

    config.pop("unexpected")
    path.write_text(json.dumps(config), encoding="utf-8")
    assert load_config(path) == config


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"limit_bytes": True}, "limit_bytes"),
        ({"limit_bytes": 1.5}, "limit_bytes"),
        ({"warning_ratio": "0.8"}, "warning_ratio"),
        ({"warning_ratio": float("inf")}, "warning_ratio"),
        ({"auto_stop_enabled": 0}, "auto_stop_enabled"),
        ({"stop_acknowledgement": None}, "stop_acknowledgement"),
        ({"xray_binary": "xray"}, "absolute path"),
        ({"xray_binary": 1}, "absolute path"),
        ({"stats_endpoint": "192.0.2.1:11085"}, "loopback"),
        ({"stats_endpoint": "localhost:11085"}, "loopback"),
        ({"stats_endpoint": "127.0.0.1:0"}, "port"),
        ({"counter_prefix": ""}, "non-empty"),
        ({"counter_prefix": "inbound"}, "non-empty"),
        ({"counter_prefix": "inbound>>>bad prefix>>>"}, "non-empty"),
        ({"state_path": "state.json"}, "absolute normalized"),
        ({"state_path": "/var/lib/../state.json"}, "absolute normalized"),
        ({"state_path": "/var/lib/state.json/"}, "absolute normalized"),
        ({"state_path": "//var/lib/state.json"}, "absolute normalized"),
        ({"service_name": "synthetic-other.service"}, "service_name"),
        ({"service_name": 1}, "service_name"),
        ({"query_user": "root"}, "query_user"),
        ({"query_user": "synthetic-user"}, "query_user"),
        ({"query_user": 1}, "query_user"),
    ],
)
def test_load_config_rejects_invalid_field_types_and_values(tmp_path, overrides, message):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(valid_config(tmp_path, **overrides)), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_config(path)


def test_run_once_revalidates_in_memory_config_before_side_effects(monkeypatch, tmp_path):
    queried = []
    monkeypatch.setattr(
        traffic_guard,
        "query_xray",
        lambda *_args: queried.append(True),
    )
    with pytest.raises(ValueError, match="unknown keys"):
        run_once(
            valid_config(tmp_path, unexpected=True),
            enforce=False,
            now=datetime(2026, 2, 1, tzinfo=UTC),
        )
    assert queried == []


def test_run_once_updates_state_without_stopping_in_decision_mode(monkeypatch, tmp_path):
    config = valid_config(tmp_path)
    monkeypatch.setattr(
        traffic_guard,
        "query_xray",
        lambda binary, endpoint, query_user: json.dumps(
            {
                "stat": [
                    {
                        "name": "inbound>>>tunnel>>>traffic>>>uplink",
                        "value": 900,
                    }
                ]
            }
        ),
    )
    disabled = []
    monkeypatch.setattr(
        traffic_guard,
        "disable_managed_egress",
        lambda: disabled.append(True),
    )

    decision = run_once(
        config,
        enforce=False,
        now=datetime(2026, 2, 1, tzinfo=UTC),
    )
    assert decision.action is Action.WARN
    assert disabled == []
    assert load_state(tmp_path / "state.json") == TrafficState("2026-02", 900, 900)


def test_run_once_persistently_disables_only_when_policy_and_runtime_are_armed(
    monkeypatch, tmp_path
):
    config = valid_config(
        tmp_path,
        auto_stop_enabled=True,
        stop_acknowledgement=AUTO_STOP_ACKNOWLEDGEMENT,
    )
    monkeypatch.setattr(
        traffic_guard,
        "query_xray",
        lambda binary, endpoint, query_user: json.dumps(
            {
                "stat": [
                    {
                        "name": "inbound>>>tunnel>>>traffic>>>uplink",
                        "value": 1000,
                    }
                ]
            }
        ),
    )
    disabled = []
    monkeypatch.setattr(
        traffic_guard,
        "disable_managed_egress",
        lambda: disabled.append(MANAGED_EGRESS_UNITS),
    )
    decision = run_once(
        config,
        enforce=True,
        now=datetime(2026, 2, 1, tzinfo=UTC),
    )
    assert decision.action is Action.STOP
    assert disabled == [MANAGED_EGRESS_UNITS]


def test_parser_requires_config():
    with pytest.raises(SystemExit):
        traffic_guard.build_parser().parse_args([])


def test_main_prints_decision_and_uses_enforce(monkeypatch, capsys, tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(traffic_guard, "load_config", lambda path: {"synthetic": True})
    monkeypatch.setattr(
        traffic_guard,
        "run_once",
        lambda config, enforce: Decision(Action.ALLOW, 1, 10, "within budget"),
    )
    assert traffic_guard.main(["--config", str(config_path), "--enforce"]) == 0
    assert '"action": "allow"' in capsys.readouterr().out


def test_main_uses_distinct_exit_for_enforced_stop(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(traffic_guard, "load_config", lambda path: {})
    monkeypatch.setattr(
        traffic_guard,
        "run_once",
        lambda config, enforce: Decision(Action.STOP, 10, 10, "armed"),
    )
    assert traffic_guard.main(["--config", str(tmp_path / "config"), "--enforce"]) == 42
    assert '"action": "stop"' in capsys.readouterr().out


@pytest.mark.parametrize(
    "error",
    [
        OSError("sensitive path"),
        TypeError("sensitive type"),
        ValueError("sensitive value"),
        subprocess.SubprocessError("sensitive command"),
        json.JSONDecodeError("sensitive JSON", "{", 0),
        UnicodeError("sensitive encoding"),
    ],
)
def test_main_redacts_errors_without_enforcement(monkeypatch, capsys, tmp_path, error):
    def fail(path):
        raise error

    disabled = []
    monkeypatch.setattr(traffic_guard, "load_config", fail)
    monkeypatch.setattr(
        traffic_guard,
        "disable_managed_egress",
        lambda: disabled.append(True),
    )
    assert traffic_guard.main(["--config", str(tmp_path / "config")]) == 2
    output = capsys.readouterr().err
    assert "traffic guard did not act" in output
    assert str(error) not in output
    assert disabled == []


def test_main_fails_closed_on_any_error_when_enforcement_is_armed(monkeypatch, capsys, tmp_path):
    def fail(path):
        raise ValueError("sensitive malformed state")

    disabled = []
    monkeypatch.setattr(traffic_guard, "load_config", fail)
    monkeypatch.setattr(
        traffic_guard,
        "disable_managed_egress",
        lambda: disabled.append(MANAGED_EGRESS_UNITS),
    )
    assert traffic_guard.main(["--config", str(tmp_path / "config"), "--enforce"]) == 42
    output = capsys.readouterr().err
    assert "failed closed" in output
    assert "sensitive malformed state" not in output
    assert disabled == [MANAGED_EGRESS_UNITS]


def test_main_reports_failed_fail_safe_shutdown(monkeypatch, capsys, tmp_path):
    def fail_config(path):
        raise ValueError("invalid")

    def fail_shutdown():
        raise subprocess.SubprocessError("sensitive service output")

    monkeypatch.setattr(traffic_guard, "load_config", fail_config)
    monkeypatch.setattr(traffic_guard, "disable_managed_egress", fail_shutdown)
    assert traffic_guard.main(["--config", str(tmp_path / "config"), "--enforce"]) == 2
    output = capsys.readouterr().err
    assert "fail-safe shutdown failed" in output
    assert "sensitive service output" not in output
