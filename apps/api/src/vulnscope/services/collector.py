from __future__ import annotations

import socket
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import dns.resolver
import httpx

from vulnscope.models import Finding, Severity
from vulnscope.policies import SAFE_PORTS

STOP = {"cancelled": True}


def _cancelled(should_stop: Callable[[], bool]) -> bool:
    return should_stop()


def inspect_tls(host: str, should_stop: Callable[[], bool]) -> dict[str, Any]:
    if _cancelled(should_stop):
        return STOP
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=3.0) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
                return {
                    "reachable": True,
                    "protocol": tls_socket.version(),
                    "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                    "not_after": certificate.get("notAfter"),
                    "issuer": certificate.get("issuer"),
                    "subject": certificate.get("subject"),
                }
    except (OSError, ssl.SSLError) as error:
        return {"reachable": False, "error": type(error).__name__}


def inspect_dns(host: str, should_stop: Callable[[], bool]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2.0
    resolver.lifetime = 3.0
    for record_type in ("A", "AAAA", "CAA", "MX"):
        if _cancelled(should_stop):
            return STOP
        try:
            answers = resolver.resolve(host, record_type, raise_on_no_answer=False)
            result[record_type] = [answer.to_text() for answer in answers]
        except (dns.resolver.DNSException, OSError):
            result[record_type] = []
    return result


def inspect_ports(host: str, should_stop: Callable[[], bool]) -> dict[str, Any]:
    open_ports: list[int] = []
    for port in SAFE_PORTS:
        if _cancelled(should_stop):
            return STOP
        try:
            with socket.create_connection((host, port), timeout=1.5):
                open_ports.append(port)
        except OSError:
            continue
    return {"checked": list(SAFE_PORTS), "open": open_ports, "payload_sent": False}


def inspect_http(host: str, should_stop: Callable[[], bool]) -> dict[str, Any]:
    if _cancelled(should_stop):
        return STOP
    base = f"https://{host}"
    headers = {
        "User-Agent": "VulnScope/0.1 authorized-low-impact-assessment",
        "Accept": "*/*",
    }
    try:
        with httpx.Client(timeout=5.0, follow_redirects=False, headers=headers) as client:
            with client.stream("GET", base) as response:
                response_headers = dict(response.headers)
                clues = {
                    key: value
                    for key, value in response_headers.items()
                    if key.lower() in {"server", "x-powered-by", "via"}
                }
                return {
                    "reachable": True,
                    "status_code": response.status_code,
                    "redirect_location": response.headers.get("location"),
                    "headers": response_headers,
                    "cookies": response.headers.get_list("set-cookie"),
                    "technology_clues": clues,
                }
    except httpx.HTTPError as error:
        return {"reachable": False, "error": type(error).__name__}


def inspect_security_txt(host: str, should_stop: Callable[[], bool]) -> dict[str, Any]:
    if _cancelled(should_stop):
        return STOP
    try:
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            with client.stream("GET", f"https://{host}/.well-known/security.txt") as response:
                return {
                    "reachable": True,
                    "status_code": response.status_code,
                    "present": response.status_code == 200,
                }
    except httpx.HTTPError as error:
        return {"reachable": False, "error": type(error).__name__}


def _header_findings(assessment_id: str, http: dict[str, Any]) -> list[Finding]:
    if not http.get("reachable"):
        return []
    headers = {key.lower(): value for key, value in http.get("headers", {}).items()}
    finding_specs = [
        (
            "strict-transport-security",
            "HSTS header was not observed",
            Severity.MEDIUM,
            "A04:2025",
            "Define an appropriate Strict-Transport-Security policy after validating HTTPS coverage.",
        ),
        (
            "content-security-policy",
            "Content-Security-Policy header was not observed",
            Severity.MEDIUM,
            "A02:2025",
            "Define and stage-test a context-specific Content-Security-Policy.",
        ),
        (
            "x-content-type-options",
            "X-Content-Type-Options header was not observed",
            Severity.LOW,
            "A02:2025",
            "Set X-Content-Type-Options: nosniff where compatible.",
        ),
        (
            "referrer-policy",
            "Referrer-Policy header was not observed",
            Severity.LOW,
            "A02:2025",
            "Set a referrer policy appropriate to the application’s privacy model.",
        ),
    ]
    findings: list[Finding] = []
    for header, title, severity, category, remediation in finding_specs:
        if header not in headers:
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    title=title,
                    severity=severity,
                    owasp_category=category,
                    confidence="observed",
                    evidence={"url": "base https endpoint", "header": header, "observed": False},
                    remediation=remediation,
                )
            )
    for cookie in http.get("cookies", []):
        lowered = cookie.lower()
        absent = [flag for flag in ("secure", "httponly", "samesite") if flag not in lowered]
        if absent:
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    title="Cookie hardening attributes require review",
                    severity=Severity.MEDIUM if "secure" in absent or "httponly" in absent else Severity.LOW,
                    owasp_category="A07:2025",
                    confidence="observed",
                    evidence={"cookie_attributes_missing": absent, "value_redacted": True},
                    remediation=(
                        "Review each cookie’s purpose and set Secure, HttpOnly, and SameSite attributes "
                        "where appropriate."
                    ),
                )
            )
    return findings


def collect_baseline_evidence(
    host: str,
    assessment_id: str,
    should_stop: Callable[[], bool],
) -> tuple[dict[str, Any], list[Finding], bool]:
    """Collect bounded metadata only; never sends attack payloads or follows redirects."""
    evidence: dict[str, Any] = {
        "target": host,
        "collected_at": datetime.now(UTC).isoformat(),
        "profile": "baseline",
    }
    probes = (
        ("tls", inspect_tls),
        ("dns", inspect_dns),
        ("http", inspect_http),
        ("security_txt", inspect_security_txt),
        ("ports", inspect_ports),
    )
    for name, probe in probes:
        if should_stop():
            return evidence, [], True
        evidence[name] = probe(host, should_stop)
        if evidence[name] == STOP:
            return evidence, [], True
    return evidence, _header_findings(assessment_id, evidence["http"]), False
