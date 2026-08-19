# Operations and engagement procedure

## Engagement intake

Before any system operator creates a VulnScope engagement, a Cyber Invasion Army reviewer should confirm the following record exists outside the application:

| Required record | Minimum content |
|---|---|
| Written authorization | Client legal entity, approver, explicit permission, effective dates, and signature or other durable approval evidence. |
| Scope statement | Exact hostname, exclusions, approved test window, environment, business owner, and escalation path. |
| Contact plan | Technical contact, emergency contact, pause authority, and incident-notification channel. |
| Test-account approval | Only when a manual OWASP task requires a designated test account; never use customer credentials. |

The portal stores an **authorization reference**, not the authorization document itself. Retain the sensitive source record within the company’s approved document-control process.

## Controlled baseline runbook

1. Record the client, exact hostname, authorization reference, technical contact, and assessment window.
2. Confirm the written authorization check box only after reviewing the external engagement record.
3. Provide the client with the unique DNS TXT record displayed in the workspace.
4. Record verification only when the expected token resolves in live mode.
5. Confirm the time window, contact availability, and scope immediately before pressing **Run bounded assessment**.
6. Monitor the activity trace. If an operational concern arises, press **Pause engagement** to block launches and **Cancel** for a running job.
7. Review each observed result and its evidence. Remove false positives in the final report process and document the review outcome.
8. Use the OWASP workspace to document separate human-led review tasks and evidence. Do not turn these tasks into unapproved automated testing.
9. Deliver a reviewed report that distinguishes observed configuration evidence, human-review results, assumptions, and assessment limitations.

## Incident or objection handling

If a client raises a concern, their service shows unexpected behavior, or the authorization is questioned:

1. Pause the engagement and cancel any active run.
2. Preserve the audit trace and note the time and reporter.
3. Notify the client through the agreed escalation channel.
4. Do not resume until the client and Cyber Invasion Army’s authorized reviewer confirm the next step in writing.

## Deployment minimums

Deploy only in a company-managed internal network, ideally with the following controls:

- organization SSO or another access-control gateway in front of the web console;
- a private PostgreSQL instance with encrypted storage and backups;
- network egress rules that match the organization’s approved engagement workflow;
- central logging for the host, reverse proxy, and application;
- a secrets manager or protected environment-file process for the database credential;
- routine backup and recovery testing for the PostgreSQL state.

VulnScope’s in-application audit trail supports assessment traceability. It does not replace centralized authentication logs, legal records, security monitoring, or incident-management procedures.
