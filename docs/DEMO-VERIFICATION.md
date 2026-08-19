# Temporary review verification

The temporary VulnScope review console was verified on 2026-08-19 using the exposed review hostname.

| Check | Verified result |
|---|---|
| Review-host allowlist | The Vite development server accepts the temporary review hostname. |
| Same-origin demo API path | The console routes `/api` requests to the local FastAPI demo service through the Vite proxy. |
| Dashboard state | The web console rendered one synthetic authorized engagement, one ready engagement, one bounded assessment, and two open findings. |
| Safety state | The UI visibly identified **DEMO MODE** and stated that the baseline profile excludes exploitation, password guessing, fuzzing, denial-of-service activity, and data access. |
| Synthetic fixture | The engagement displayed `demo-assessment.example` for synthetic client `Northwind Training Ltd.` with authorization reference `CIIA-DEMO-2026-01`. |

## Assessor workspace verification

The temporary console successfully opened the synthetic client workspace. It displayed the authorization record, verified domain proof, approved assessment window, the complete OWASP Top 10:2025 human-review plan, existing evidence-led findings, remediation guidance, and the engagement audit trace.

A browser-triggered **Run bounded assessment** action was also verified in demo mode. The interface confirmed that the assessment was queued, increased the synthetic assessment count from one to two, and continued to identify all findings as requiring assessor review. No external target was contacted.

The temporary review configuration is only for demonstration. Production use must follow the company-controlled deployment process in `docs/OPERATIONS.md`.
