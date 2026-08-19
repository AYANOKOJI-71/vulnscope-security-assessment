from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class EngagementState(StrEnum):
    PENDING_VERIFICATION = "pending_verification"
    READY = "ready"
    PAUSED = "paused"
    CLOSED = "closed"


class AssessmentState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Engagement(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    client_name: str = Field(min_length=2, max_length=120)
    target_host: str = Field(min_length=3, max_length=253)
    authorization_reference: str = Field(min_length=3, max_length=120)
    technical_contact: str = Field(min_length=3, max_length=160)
    window_starts_at: datetime
    window_ends_at: datetime
    written_authorization_confirmed: bool = False
    verification_token: str
    dns_record_name: str
    ownership_verified: bool = False
    state: EngagementState = EngagementState.PENDING_VERIFICATION
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("target_host")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        normalized = value.strip().lower().removeprefix("https://").removeprefix("http://")
        return normalized.split("/")[0]


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    assessment_id: str
    title: str
    severity: Severity
    owasp_category: str
    confidence: str
    evidence: dict[str, Any]
    remediation: str
    verified: bool = False
    created_at: datetime = Field(default_factory=utc_now)


class Assessment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    engagement_id: str
    requested_by: str
    profile: str = "baseline"
    state: AssessmentState = AssessmentState.QUEUED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    block_reason: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: str
    actor: str
    engagement_id: str | None = None
    assessment_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class EngagementCreate(BaseModel):
    client_name: str
    target_host: str
    authorization_reference: str
    technical_contact: str
    window_starts_at: datetime
    window_ends_at: datetime
    written_authorization_confirmed: bool


class AssessmentStart(BaseModel):
    requested_by: str = Field(min_length=2, max_length=80)
    operator_confirmation: bool
    profile: str = "baseline"


class VerificationConfirm(BaseModel):
    operator: str = Field(min_length=2, max_length=80)
    demo_proof: bool = False
