# VulnScope

> **A local, client-authorized vulnerability-assessment workspace for Cyber Invasion Army.**

VulnScope is designed to turn a signed client engagement into a traceable assessment workflow. It combines bounded technical evidence collection with an **OWASP Top 10:2025-aligned human assessor workspace**, documented scope gates, client-ready findings, remediation guidance, and a durable audit trail.

It is deliberately **not** a one-click exploitation framework or an autonomous replacement for a qualified security assessor. The included collection profile is restricted to low-impact metadata and configuration checks. Human-led tasks require a written engagement and explicit scope review.

## What it does

| Workflow step | Portal behavior | Evidence and guardrail |
|---|---|---|
| Record engagement | Captures client, target hostname, technical contact, authorization reference, and approved time window. | A run cannot start without a recorded authorization confirmation. |
| Verify target control | Creates a unique DNS TXT challenge under `_vulnscope.<target>`. | In live mode, the expected token must resolve before execution. |
| Execute baseline profile | Inspects TLS metadata, DNS records, response headers, cookie flags, `security.txt`, technology clues, and only TCP ports **80, 443, and 8443**. | No redirect following, payload injection, password attempts, broad discovery, or data access. |
| Review OWASP work | Provides an OWASP Top 10:2025 assessor checklist for scope-approved, human-reviewed work. | The portal records evidence and remediation; it does not automate invasive testing. |
| Report and retest | Presents severity, evidence, remediation recommendations, activity, and audit history. | Findings are explicitly marked for assessor review before client delivery. |

## Safety boundary

The repository enforces the following controls in application logic, not only in the user interface:

1. **Hostname-only allowlisting.** URLs, wildcards, ranges, and raw IP targets are rejected.
2. **Written authorization record.** A recorded authorization reference and confirmation are required.
3. **DNS TXT control proof.** Live execution requires an expected challenge token at `_vulnscope.<target>`.
4. **Approved time window.** Runs outside the supplied window are blocked; windows are capped at 12 hours.
5. **One bounded profile.** Only the `baseline` profile can run.
6. **Hard exclusions.** Exploitation, credential attacks, fuzzing, denial-of-service activity, data access, and broad discovery are excluded.
7. **Stop controls.** A paused engagement blocks new work. Cancellation is recorded and the collector checks for it before each probe.
8. **Auditability.** Engagement, verification, queue, start, completion, cancellation, and finding events are recorded.

> **Use only against assets for which your organization has written authority and a defined scope.** Do not disable these safety gates to test targets outside that agreement.

## Quick start: safe deterministic demo

The default compose configuration is intentionally in `DEMO_MODE=true`. It makes **no outbound network connections**. The seeded engagement uses an IETF documentation hostname and fixture address space (`192.0.2.0/24`).

```bash
docker compose up --build
```

Open the following services:

| Service | Address |
|---|---|
| Web console | `http://localhost:5186` |
| API documentation | `http://localhost:4700/docs` |
| Health check | `http://localhost:4700/healthz` |

The initial dashboard includes **Northwind Training Ltd.**, an explicitly synthetic demo record. Press **Run bounded assessment** to create fixture findings. No external hostname is contacted.

## Authorized live use

Before enabling live collection, deploy the portal to a **company-controlled internal environment** behind your identity provider, VPN, or a restrictive network policy. Do not expose the local operator console directly to the public internet.

1. Replace the default PostgreSQL password and set a private `DATABASE_URL`.
2. Set `DEMO_MODE=false` for the API service.
3. Set `ALLOWED_WEB_ORIGINS` to the internal web-console origin.
4. Restrict inbound access to the assessment team and confirm outbound egress and DNS policies.
5. For every engagement, retain a signed authorization and scope document outside the portal; record its unique reference in VulnScope.
6. Register one exact target hostname and a defined test window. Publish the displayed DNS TXT proof on that exact hostname.
7. Require an assessor to review the scope and confirm immediately before launching the `baseline` profile.
8. Review collected findings, remove irrelevant or duplicate observations, and obtain a second assessor’s review before delivery.

The portal intentionally cannot perform browser-driven authenticated assessments, password testing, injection payloads, fuzzing, exploitation, or load generation. If an engagement legitimately needs an additional activity, conduct a separate risk review, obtain a scope amendment, and use an approved tool under human supervision—not this baseline profile.

## OWASP mapping

The workspace uses the current [OWASP Top 10:2025](https://owasp.org/Top10/2025/en/) categories as a reporting and review taxonomy. The baseline collector can surface supporting observations primarily around security configuration, cryptographic transport, authentication cookie flags, and disclosure/alerting contact information. It cannot validate every OWASP category automatically.

| Category | Workspace support |
|---|---|
| A01 Broken Access Control | Human-led authorization-matrix review using approved test accounts. |
| A02 Security Misconfiguration | Baseline headers, security configuration observations, and assessor review. |
| A03 Software Supply Chain Failures | Client-provided inventory, attestation, and patch-evidence review. |
| A04 Cryptographic Failures | TLS metadata plus human review of protection design. |
| A05 Injection | Scope-approved, non-destructive human review only; no payload generation. |
| A06 Insecure Design | Trust-boundary and abuse-case review with the system owner. |
| A07 Authentication Failures | Test-account session and recovery review; no credential guessing. |
| A08 Integrity Failures | Build/deployment evidence review; no artifact modification. |
| A09 Logging and Alerting Failures | Approved-event alerting evidence review; no high-volume telemetry. |
| A10 Exceptional Conditions | Negative-path review with owner; no malformed traffic or availability testing. |

## Local development

### API

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/uvicorn vulnscope.main:app --reload --host 0.0.0.0 --port 4700
```

### Web console

```bash
cd apps/web
npx --yes pnpm@10.6.3 install
npx --yes pnpm@10.6.3 dev
```

## Quality commands

```bash
.venv/bin/ruff check apps/api/src tests
.venv/bin/pytest -q
cd apps/web && npx --yes pnpm@10.6.3 test && npx --yes pnpm@10.6.3 build
```

## Architecture

```text
React/Vite console (5186)
        │
        ▼
FastAPI policy gate + audit trail (4700) ───── PostgreSQL state
        │
        ├── records engagement, authorization reference, and scope window
        ├── verifies DNS TXT ownership token
        ├── launches bounded collector only after every gate passes
        └── writes assessment, evidence, findings, and audit events
```

## References

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/en/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-115: Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
