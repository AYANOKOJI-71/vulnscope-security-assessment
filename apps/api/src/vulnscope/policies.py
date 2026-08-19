from __future__ import annotations

import ipaddress
import re
import secrets
from datetime import UTC, datetime

from vulnscope.models import Engagement, EngagementState

SAFE_PORTS = (80, 443, 8443)
SAFE_PROFILE = "baseline"
OWASP_2025 = (
    ("A01:2025", "Broken Access Control"),
    ("A02:2025", "Security Misconfiguration"),
    ("A03:2025", "Software Supply Chain Failures"),
    ("A04:2025", "Cryptographic Failures"),
    ("A05:2025", "Injection"),
    ("A06:2025", "Insecure Design"),
    ("A07:2025", "Authentication Failures"),
    ("A08:2025", "Software or Data Integrity Failures"),
    ("A09:2025", "Security Logging and Alerting Failures"),
    ("A10:2025", "Mishandling of Exceptional Conditions"),
)

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def validate_public_hostname(host: str) -> str:
    normalized = host.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not _HOST_RE.fullmatch(normalized):
        raise ValueError("A public DNS hostname is required; URLs, IP ranges, and wildcard scopes are not accepted.")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return normalized
    raise ValueError("Raw IP targets are blocked by the web-assessment profile.")


def build_verification(host: str) -> tuple[str, str]:
    token = f"vulnscope={secrets.token_urlsafe(20)}"
    return f"_vulnscope.{host}", token


def execution_block_reason(
    engagement: Engagement,
    profile: str,
    now: datetime | None = None,
) -> str | None:
    now = now or datetime.now(UTC)
    if profile != SAFE_PROFILE:
        return "Only the explicitly bounded baseline assessment profile is available."
    if not engagement.written_authorization_confirmed:
        return "Written authorization has not been recorded."
    if not engagement.ownership_verified:
        return "DNS ownership verification has not been completed."
    if engagement.state != EngagementState.READY:
        return f"Engagement state '{engagement.state}' does not permit execution."
    if not engagement.window_starts_at <= now <= engagement.window_ends_at:
        return "The approved assessment window is not currently active."
    return None


def manual_review_tasks() -> list[dict[str, str]]:
    return [
        {
            "owasp": "A01:2025",
            "title": "Access-control review",
            "task": (
                "Using client-provided test accounts, review the approved authorization matrix and record "
                "expected versus observed access decisions."
            ),
        },
        {
            "owasp": "A02:2025",
            "title": "Configuration review",
            "task": (
                "Review exposed response headers, deployment settings, and documented hardening controls; "
                "attach approved evidence only."
            ),
        },
        {
            "owasp": "A03:2025",
            "title": "Supply-chain review",
            "task": (
                "Review the client-provided software inventory, dependency attestations, and patch-management "
                "evidence; no package discovery is attempted by the portal."
            ),
        },
        {
            "owasp": "A04:2025",
            "title": "Cryptography review",
            "task": (
                "Review the collected TLS metadata and client-provided data-protection design evidence against "
                "the engagement scope."
            ),
        },
        {
            "owasp": "A05:2025",
            "title": "Input-handling review",
            "task": (
                "Document approved manual validation using non-destructive test accounts and minimal test data. "
                "Payload generation and exploitation are outside this profile."
            ),
        },
        {
            "owasp": "A06:2025",
            "title": "Design review",
            "task": "Review client-provided trust-boundary and abuse-case documentation with the system owner.",
        },
        {
            "owasp": "A07:2025",
            "title": "Authentication review",
            "task": (
                "Review login, recovery, and session controls using designated test accounts. No password "
                "guessing or credential stuffing is permitted."
            ),
        },
        {
            "owasp": "A08:2025",
            "title": "Integrity review",
            "task": (
                "Review build, deployment, and update integrity evidence supplied by the client; do not alter "
                "artifacts."
            ),
        },
        {
            "owasp": "A09:2025",
            "title": "Logging and alerting review",
            "task": (
                "Review the client’s alerting evidence for approved test events; do not create high-volume "
                "telemetry."
            ),
        },
        {
            "owasp": "A10:2025",
            "title": "Exceptional-condition review",
            "task": (
                "Review approved negative-path behavior with the system owner. Do not submit malformed traffic "
                "or conduct availability testing."
            ),
        },
    ]
