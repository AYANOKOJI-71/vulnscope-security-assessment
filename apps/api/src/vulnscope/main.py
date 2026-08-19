from __future__ import annotations

import asyncio
import os
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import dns.resolver
from fastapi import BackgroundTasks, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from vulnscope.models import (
    Assessment,
    AssessmentStart,
    AssessmentState,
    Engagement,
    EngagementCreate,
    EngagementState,
    Finding,
    Severity,
    VerificationConfirm,
    utc_now,
)
from vulnscope.policies import (
    OWASP_2025,
    build_verification,
    execution_block_reason,
    manual_review_tasks,
    validate_public_hostname,
)
from vulnscope.repository import MemoryRepository, PostgresRepository
from vulnscope.services.collector import collect_baseline_evidence

DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
DATABASE_URL = os.getenv("DATABASE_URL", "")
_cancellations: dict[str, threading.Event] = {}


def _repository() -> MemoryRepository:
    if DATABASE_URL:
        try:
            return PostgresRepository(DATABASE_URL)
        except Exception:  # pragma: no cover - PostgreSQL may start after the API service.
            pass
    return MemoryRepository()


repository = _repository()


@asynccontextmanager
async def lifespan(_: FastAPI):
    if DEMO_MODE:
        repository.seed_demo()
    yield


app = FastAPI(
    title="VulnScope",
    version="0.1.0",
    description="Client-authorized OWASP-aligned security assessment workspace with bounded evidence collection.",
    lifespan=lifespan,
)
origins = [
    item.strip()
    for item in os.getenv("ALLOWED_WEB_ORIGINS", "http://localhost:5186").split(",")
    if item.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="The requested record does not exist.")


def _require_engagement(engagement_id: str) -> Engagement:
    engagement = repository.get_engagement(engagement_id)
    if not engagement:
        raise _not_found()
    return engagement


def _require_assessment(assessment_id: str) -> Assessment:
    assessment = repository.get_assessment(assessment_id)
    if not assessment:
        raise _not_found()
    return assessment


def _fixture_evidence(assessment_id: str) -> tuple[dict[str, Any], list[Finding]]:
    evidence = {
        "demo_mode": True,
        "notice": "This deterministic fixture did not connect to a remote target.",
        "tls": {
            "reachable": True,
            "protocol": "TLSv1.2",
            "not_after": "Dec 31 23:59:59 2027 GMT",
        },
        "dns": {"A": ["192.0.2.20"], "AAAA": [], "CAA": [], "MX": []},
        "http": {
            "reachable": True,
            "status_code": 200,
            "headers": {"server": "fixture-edge", "x-content-type-options": "nosniff"},
            "cookies": ["fixture_session=redacted; Path=/; SameSite=Lax"],
        },
        "security_txt": {"reachable": True, "status_code": 404, "present": False},
        "ports": {"checked": [80, 443, 8443], "open": [443], "payload_sent": False},
    }
    findings = [
        Finding(
            assessment_id=assessment_id,
            title="Content-Security-Policy header was not observed",
            severity=Severity.MEDIUM,
            owasp_category="A02:2025",
            confidence="fixture",
            evidence={
                "source": "deterministic demo fixture",
                "header": "content-security-policy",
                "observed": False,
            },
            remediation=(
                "Define a context-appropriate Content-Security-Policy and validate it in staging before deployment."
            ),
        ),
        Finding(
            assessment_id=assessment_id,
            title="Cookie hardening attributes require review",
            severity=Severity.MEDIUM,
            owasp_category="A07:2025",
            confidence="fixture",
            evidence={
                "source": "deterministic demo fixture",
                "cookie_attributes_missing": ["secure", "httponly"],
            },
            remediation=(
                "Review the cookie’s purpose and set Secure and HttpOnly where compatible with the session model."
            ),
        ),
        Finding(
            assessment_id=assessment_id,
            title="security.txt was not observed",
            severity=Severity.INFO,
            owasp_category="A09:2025",
            confidence="fixture",
            evidence={
                "source": "deterministic demo fixture",
                "path": "/.well-known/security.txt",
                "status_code": 404,
            },
            remediation=(
                "Consider publishing a security.txt file that gives coordinated-disclosure contact details."
            ),
        ),
    ]
    return evidence, findings


async def run_assessment(assessment_id: str) -> None:
    assessment = _require_assessment(assessment_id)
    engagement = _require_engagement(assessment.engagement_id)
    cancellation = _cancellations.setdefault(assessment_id, threading.Event())
    assessment.state = AssessmentState.RUNNING
    assessment.started_at = utc_now()
    repository.save_assessment(assessment, "system", "assessment.started", {"profile": assessment.profile})

    if DEMO_MODE:
        evidence, findings = _fixture_evidence(assessment.id)
        cancelled = cancellation.is_set()
    else:
        evidence, findings, cancelled = await asyncio.to_thread(
            collect_baseline_evidence,
            engagement.target_host,
            assessment.id,
            cancellation.is_set,
        )

    assessment.evidence = evidence
    assessment.completed_at = utc_now()
    assessment.state = AssessmentState.CANCELLED if cancelled else AssessmentState.COMPLETED
    event_type = "assessment.cancelled" if cancelled else "assessment.completed"
    repository.save_assessment(assessment, "system", event_type, {"finding_count": 0 if cancelled else len(findings)})
    if not cancelled:
        repository.add_findings(findings, "system", assessment)
    _cancellations.pop(assessment_id, None)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"status": "ok", "demo_mode": DEMO_MODE, "profile": "baseline-only"}


@app.get("/api/catalog/owasp")
def get_owasp_catalog() -> dict[str, Any]:
    categories = [{"id": item[0], "name": item[1]} for item in OWASP_2025]
    return {"version": "OWASP Top 10:2025", "categories": categories, "manual_tasks": manual_review_tasks()}


@app.get("/api/dashboard")
def get_dashboard() -> dict[str, Any]:
    engagements = repository.list_engagements()
    assessments = repository.list_assessments()
    findings = [finding for assessment in assessments for finding in repository.list_findings(assessment.id)]
    return {
        "demo_mode": DEMO_MODE,
        "guardrails": {
            "requires_written_authorization": True,
            "requires_dns_ownership_verification": True,
            "allowed_ports": [80, 443, 8443],
            "exclusions": [
                "exploitation",
                "credential attacks",
                "fuzzing",
                "denial of service",
                "data access",
                "broad discovery",
            ],
        },
        "counts": {
            "engagements": len(engagements),
            "ready_engagements": sum(item.state == EngagementState.READY for item in engagements),
            "assessments": len(assessments),
            "open_findings": len(findings),
        },
        "engagements": engagements,
        "recent_assessments": assessments[:6],
    }


@app.post("/api/engagements", status_code=status.HTTP_201_CREATED)
def create_engagement(payload: EngagementCreate) -> Engagement:
    try:
        host = validate_public_hostname(payload.target_host)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from error
    if payload.window_ends_at <= payload.window_starts_at:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The assessment window must end after it starts.",
        )
    if payload.window_ends_at - payload.window_starts_at > timedelta(hours=12):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Assessment windows are capped at 12 hours.",
        )
    record_name, token = build_verification(host)
    engagement_data = payload.model_dump()
    engagement_data["target_host"] = host
    engagement = Engagement(
        **engagement_data,
        verification_token=token,
        dns_record_name=record_name,
        state=EngagementState.PENDING_VERIFICATION,
    )
    return repository.create_engagement(engagement, "operator")


@app.get("/api/engagements")
def list_engagements() -> list[Engagement]:
    return repository.list_engagements()


@app.get("/api/engagements/{engagement_id}")
def get_engagement(engagement_id: str) -> Engagement:
    return _require_engagement(engagement_id)


@app.post("/api/engagements/{engagement_id}/verify")
def verify_engagement(engagement_id: str, payload: VerificationConfirm) -> Engagement:
    engagement = _require_engagement(engagement_id)
    if not engagement.written_authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Written authorization must be recorded before verification.",
        )
    verified = False
    if DEMO_MODE:
        verified = payload.demo_proof and engagement.target_host.endswith(".example")
    else:
        try:
            records = dns.resolver.resolve(engagement.dns_record_name, "TXT", lifetime=5)
            verified = any(engagement.verification_token in record.to_text().strip('"') for record in records)
        except dns.resolver.DNSException:
            verified = False
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The expected DNS TXT verification token was not found.",
        )
    engagement.ownership_verified = True
    engagement.state = EngagementState.READY
    method = "demo" if DEMO_MODE else "dns_txt"
    return repository.save_engagement(engagement, payload.operator, "engagement.verified", {"method": method})


@app.post("/api/engagements/{engagement_id}/pause")
def pause_engagement(engagement_id: str) -> Engagement:
    engagement = _require_engagement(engagement_id)
    engagement.state = EngagementState.PAUSED
    return repository.save_engagement(engagement, "operator", "engagement.paused", {})


@app.post("/api/engagements/{engagement_id}/assessments", status_code=status.HTTP_202_ACCEPTED)
def start_assessment(
    engagement_id: str,
    payload: AssessmentStart,
    background_tasks: BackgroundTasks,
) -> Assessment:
    engagement = _require_engagement(engagement_id)
    if not payload.operator_confirmation:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The operator must confirm the approved scope immediately before execution.",
        )
    block_reason = execution_block_reason(engagement, payload.profile)
    assessment = Assessment(
        engagement_id=engagement_id,
        requested_by=payload.requested_by,
        profile=payload.profile,
        block_reason=block_reason,
    )
    if block_reason:
        assessment.state = AssessmentState.BLOCKED
        return repository.create_assessment(assessment, payload.requested_by)
    repository.create_assessment(assessment, payload.requested_by)
    _cancellations[assessment.id] = threading.Event()
    background_tasks.add_task(run_assessment, assessment.id)
    return assessment


@app.get("/api/assessments/{assessment_id}")
def get_assessment(assessment_id: str) -> dict[str, Any]:
    assessment = _require_assessment(assessment_id)
    return {"assessment": assessment, "findings": repository.list_findings(assessment.id)}


@app.post("/api/assessments/{assessment_id}/cancel")
def cancel_assessment(assessment_id: str) -> Assessment:
    assessment = _require_assessment(assessment_id)
    terminal_states = {AssessmentState.COMPLETED, AssessmentState.CANCELLED, AssessmentState.BLOCKED}
    if assessment.state in terminal_states:
        return assessment
    _cancellations.setdefault(assessment_id, threading.Event()).set()
    assessment.state = AssessmentState.CANCEL_REQUESTED
    return repository.save_assessment(assessment, "operator", "assessment.cancel.requested", {})


@app.get("/api/engagements/{engagement_id}/workspace")
def get_workspace(engagement_id: str) -> dict[str, Any]:
    engagement = _require_engagement(engagement_id)
    assessments = repository.list_assessments(engagement_id)
    findings = [finding for assessment in assessments for finding in repository.list_findings(assessment.id)]
    return {
        "engagement": engagement,
        "assessments": assessments,
        "findings": findings,
        "manual_tasks": manual_review_tasks(),
        "audit": repository.list_audit(engagement_id),
    }


@app.get("/api/engagements/{engagement_id}/report")
def get_report(engagement_id: str) -> dict[str, Any]:
    engagement = _require_engagement(engagement_id)
    assessments = repository.list_assessments(engagement_id)
    findings = [finding for assessment in assessments for finding in repository.list_findings(assessment.id)]
    by_severity = {level.value: sum(item.severity == level for item in findings) for level in Severity}
    scope = {
        "target": engagement.target_host,
        "authorization_reference": engagement.authorization_reference,
        "window": [engagement.window_starts_at, engagement.window_ends_at],
    }
    methodology = (
        "OWASP Top 10:2025-aligned evidence collection and scoped human review. No exploitation, "
        "credential attacks, fuzzing, denial-of-service testing, broad discovery, or unauthorized data access occurred."
    )
    return {
        "title": f"VulnScope Assessment Report — {engagement.client_name}",
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": scope,
        "methodology": methodology,
        "summary": {
            "assessment_count": len(assessments),
            "finding_count": len(findings),
            "by_severity": by_severity,
        },
        "findings": findings,
        "manual_review_tasks": manual_review_tasks(),
        "limitations": (
            "Findings require assessor review and client validation; a bounded automated check cannot replace "
            "a full security assessment."
        ),
    }
