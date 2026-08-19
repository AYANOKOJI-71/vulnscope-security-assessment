from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

import psycopg

from vulnscope.models import Assessment, AssessmentState, AuditEvent, Engagement, EngagementState, Finding, utc_now


class MemoryRepository:
    def __init__(self) -> None:
        self.engagements: dict[str, Engagement] = {}
        self.assessments: dict[str, Assessment] = {}
        self.findings: dict[str, list[Finding]] = defaultdict(list)
        self.audits: list[AuditEvent] = []

    def _persist(self) -> None:
        return None

    def audit(self, event_type: str, actor: str, **kwargs: Any) -> AuditEvent:
        event = AuditEvent(event_type=event_type, actor=actor, **kwargs)
        self.audits.append(event)
        self._persist()
        return event

    def create_engagement(self, engagement: Engagement, actor: str) -> Engagement:
        self.engagements[engagement.id] = engagement
        self.audit("engagement.created", actor, engagement_id=engagement.id, detail={"target": engagement.target_host})
        return engagement

    def get_engagement(self, engagement_id: str) -> Engagement | None:
        return self.engagements.get(engagement_id)

    def list_engagements(self) -> list[Engagement]:
        return sorted(self.engagements.values(), key=lambda item: item.created_at, reverse=True)

    def save_engagement(
        self,
        engagement: Engagement,
        actor: str,
        event_type: str,
        detail: dict[str, Any],
    ) -> Engagement:
        self.engagements[engagement.id] = engagement
        self.audit(event_type, actor, engagement_id=engagement.id, detail=detail)
        return engagement

    def create_assessment(self, assessment: Assessment, actor: str) -> Assessment:
        self.assessments[assessment.id] = assessment
        self.audit(
            "assessment.queued",
            actor,
            engagement_id=assessment.engagement_id,
            assessment_id=assessment.id,
        )
        return assessment

    def get_assessment(self, assessment_id: str) -> Assessment | None:
        return self.assessments.get(assessment_id)

    def list_assessments(self, engagement_id: str | None = None) -> list[Assessment]:
        result = self.assessments.values()
        if engagement_id:
            result = (item for item in result if item.engagement_id == engagement_id)
        return sorted(result, key=lambda item: item.created_at, reverse=True)

    def save_assessment(
        self,
        assessment: Assessment,
        actor: str,
        event_type: str,
        detail: dict[str, Any] | None = None,
    ) -> Assessment:
        self.assessments[assessment.id] = assessment
        self.audit(
            event_type,
            actor,
            engagement_id=assessment.engagement_id,
            assessment_id=assessment.id,
            detail=detail or {},
        )
        return assessment

    def add_findings(self, findings: list[Finding], actor: str, assessment: Assessment) -> None:
        self.findings[assessment.id].extend(findings)
        self.audit(
            "assessment.findings.recorded",
            actor,
            engagement_id=assessment.engagement_id,
            assessment_id=assessment.id,
            detail={"count": len(findings)},
        )

    def list_findings(self, assessment_id: str) -> list[Finding]:
        return list(self.findings.get(assessment_id, []))

    def list_audit(self, engagement_id: str | None = None) -> list[AuditEvent]:
        events = self.audits
        if engagement_id is not None:
            events = [item for item in events if item.engagement_id == engagement_id]
        return sorted(events, key=lambda item: item.created_at, reverse=True)

    def serialize(self) -> dict[str, Any]:
        return {
            "engagements": [item.model_dump(mode="json") for item in self.engagements.values()],
            "assessments": [item.model_dump(mode="json") for item in self.assessments.values()],
            "findings": {
                key: [item.model_dump(mode="json") for item in value] for key, value in self.findings.items()
            },
            "audits": [item.model_dump(mode="json") for item in self.audits],
        }

    def hydrate(self, state: dict[str, Any]) -> None:
        self.engagements = {item["id"]: Engagement.model_validate(item) for item in state.get("engagements", [])}
        self.assessments = {item["id"]: Assessment.model_validate(item) for item in state.get("assessments", [])}
        self.findings = defaultdict(
            list,
            {key: [Finding.model_validate(item) for item in value] for key, value in state.get("findings", {}).items()},
        )
        self.audits = [AuditEvent.model_validate(item) for item in state.get("audits", [])]

    def seed_demo(self) -> None:
        if any(item.target_host == "demo-assessment.example" for item in self.engagements.values()):
            return
        now = utc_now()
        engagement = Engagement(
            client_name="Northwind Training Ltd.",
            target_host="demo-assessment.example",
            authorization_reference="CIIA-DEMO-2026-01",
            technical_contact="security-contact@example.test",
            window_starts_at=now,
            window_ends_at=now.replace(year=now.year + 1),
            written_authorization_confirmed=True,
            verification_token="vulnscope=demo-verification-only",
            dns_record_name="_vulnscope.demo-assessment.example",
            ownership_verified=True,
            state=EngagementState.READY,
        )
        self.create_engagement(engagement, "demo-seed")
        assessment = Assessment(
            engagement_id=engagement.id,
            requested_by="demo-seed",
            state=AssessmentState.COMPLETED,
            started_at=now,
            completed_at=now,
            evidence={"demo_mode": True, "notice": "Stored fixture only; no network activity occurred."},
        )
        self.create_assessment(assessment, "demo-seed")
        self.add_findings(
            [
                Finding(
                    assessment_id=assessment.id,
                    title="Content-Security-Policy header was not observed",
                    severity="medium",
                    owasp_category="A02:2025",
                    confidence="fixture",
                    evidence={
                        "source": "deterministic demo fixture",
                        "header": "content-security-policy",
                        "observed": False,
                    },
                    remediation=(
                        "Define a context-appropriate Content-Security-Policy and validate it in a staging environment."
                    ),
                ),
                Finding(
                    assessment_id=assessment.id,
                    title="Demo TLS configuration requires human review",
                    severity="low",
                    owasp_category="A04:2025",
                    confidence="fixture",
                    evidence={"source": "deterministic demo fixture", "review": "certificate and protocol policy"},
                    remediation=(
                        "Review TLS protocol, cipher, certificate lifecycle, and HSTS policy against the "
                        "client baseline."
                    ),
                ),
            ],
            "demo-seed",
            assessment,
        )


class PostgresRepository(MemoryRepository):
    """Small local-deployment persistence adapter using a transactional JSON document.

    The JSON state keeps the example compact while PostgreSQL remains the durable source of truth.
    """

    def __init__(self, database_url: str) -> None:
        super().__init__()
        self.database_url = database_url
        with psycopg.connect(self.database_url) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS vulnscope_state ("
                "id SMALLINT PRIMARY KEY, state JSONB NOT NULL, "
                "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"
            )
            row = connection.execute("SELECT state FROM vulnscope_state WHERE id = 1").fetchone()
        if row:
            self.hydrate(row[0])

    def _persist(self) -> None:
        payload = json.dumps(self.serialize())
        with psycopg.connect(self.database_url) as connection:
            connection.execute(
                "INSERT INTO vulnscope_state (id, state) VALUES (1, %s::jsonb) "
                "ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = NOW()",
                (payload,),
            )
