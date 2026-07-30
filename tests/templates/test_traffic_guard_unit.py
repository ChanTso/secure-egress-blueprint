from pathlib import Path

UNIT_TEMPLATE = (
    Path(__file__).parents[2]
    / "ansible"
    / "roles"
    / "secure_egress"
    / "templates"
    / "secure-egress-traffic-guard.service.j2"
)


def test_traffic_guard_unit_orders_without_requiring_the_guarded_service():
    unit = UNIT_TEMPLATE.read_text(encoding="utf-8")
    assert "After=secure-egress-xray.service" in unit
    assert "Requires=" not in unit
    assert "BindsTo=" not in unit
    assert "PartOf=" not in unit
