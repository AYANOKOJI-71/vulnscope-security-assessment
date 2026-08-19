from __future__ import annotations

from vulnscope.services.collector import collect_baseline_evidence


def test_cancellation_short_circuits_before_any_network_probe() -> None:
    evidence, findings, cancelled = collect_baseline_evidence(
        "authorized-client.example",
        "assessment-id",
        lambda: True,
    )
    assert cancelled is True
    assert findings == []
    assert evidence["target"] == "authorized-client.example"
    assert "tls" not in evidence
