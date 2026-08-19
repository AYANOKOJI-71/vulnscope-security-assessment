from __future__ import annotations

from datetime import timedelta

import pytest
import vulnscope.main as main
from fastapi.testclient import TestClient
from vulnscope.models import utc_now
from vulnscope.repository import MemoryRepository


@pytest.fixture()
def client() -> TestClient:
    main.DEMO_MODE = True
    main.repository = MemoryRepository()
    main._cancellations.clear()
    with TestClient(main.app) as test_client:
        yield test_client


def engagement_payload(**overrides: object) -> dict[str, object]:
    now = utc_now()
    payload: dict[str, object] = {
        "client_name": "Example Client",
        "target_host": "authorized-client.example",
        "authorization_reference": "CIIA-2026-TEST",
        "technical_contact": "security@example.test",
        "window_starts_at": (now - timedelta(minutes=5)).isoformat(),
        "window_ends_at": (now + timedelta(hours=1)).isoformat(),
        "written_authorization_confirmed": True,
    }
    payload.update(overrides)
    return payload


def test_scope_rejects_raw_ip_targets(client: TestClient) -> None:
    response = client.post("/api/engagements", json=engagement_payload(target_host="192.0.2.20"))
    assert response.status_code == 422
    assert "hostname" in response.json()["detail"].lower()


def test_assessment_is_blocked_until_dns_proof_is_recorded(client: TestClient) -> None:
    engagement = client.post("/api/engagements", json=engagement_payload()).json()
    response = client.post(
        f"/api/engagements/{engagement['id']}/assessments",
        json={"requested_by": "assessor", "operator_confirmation": True, "profile": "baseline"},
    )
    assert response.status_code == 202
    assert response.json()["state"] == "blocked"
    assert "verification" in response.json()["block_reason"].lower()


def test_verified_demo_engagement_runs_only_fixture_collection(client: TestClient) -> None:
    engagement = client.post("/api/engagements", json=engagement_payload()).json()
    verified = client.post(
        f"/api/engagements/{engagement['id']}/verify",
        json={"operator": "assessor", "demo_proof": True},
    )
    assert verified.status_code == 200
    assert verified.json()["state"] == "ready"
    queued = client.post(
        f"/api/engagements/{engagement['id']}/assessments",
        json={"requested_by": "assessor", "operator_confirmation": True, "profile": "baseline"},
    ).json()
    detail = client.get(f"/api/assessments/{queued['id']}").json()
    assert detail["assessment"]["state"] == "completed"
    assert detail["assessment"]["evidence"]["demo_mode"] is True
    assert len(detail["findings"]) == 3


def test_pause_blocks_future_assessments(client: TestClient) -> None:
    engagement = client.post("/api/engagements", json=engagement_payload()).json()
    client.post(f"/api/engagements/{engagement['id']}/verify", json={"operator": "assessor", "demo_proof": True})
    paused = client.post(f"/api/engagements/{engagement['id']}/pause").json()
    assert paused["state"] == "paused"
    blocked = client.post(
        f"/api/engagements/{engagement['id']}/assessments",
        json={"requested_by": "assessor", "operator_confirmation": True, "profile": "baseline"},
    ).json()
    assert blocked["state"] == "blocked"
    assert "paused" in blocked["block_reason"]
