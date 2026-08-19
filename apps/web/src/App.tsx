import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, Assessment, Dashboard, Engagement, Finding, Workspace } from "./api";

const defaultStart = new Date().toISOString().slice(0, 16);
const defaultEnd = new Date(Date.now() + 60 * 60 * 1000).toISOString().slice(0, 16);

function fmt(value?: string): string {
  return value ? new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—";
}

function Badge({ value }: { value: string }) {
  return <span className={`badge badge-${value.toLowerCase().replaceAll("_", "-")}`}>{value.replaceAll("_", " ")}</span>;
}

function SeverityPill({ value }: { value: string }) {
  return <span className={`severity severity-${value}`}>{value}</span>;
}

export default function App() {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(true);
  const [operator, setOperator] = useState("CIIA assessor");

  const refreshDashboard = async () => {
    try {
      setError("");
      const next = await api<Dashboard>("/api/dashboard");
      setDashboard(next);
      if (workspace) await selectWorkspace(workspace.engagement.id, false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The API could not be reached.");
    } finally {
      setLoading(false);
    }
  };

  const selectWorkspace = async (id: string, displayNotice = true) => {
    try {
      const next = await api<Workspace>(`/api/engagements/${id}/workspace`);
      setWorkspace(next);
      if (displayNotice) setNotice(`Opened ${next.engagement.client_name}'s controlled workspace.`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load engagement workspace.");
    }
  };

  useEffect(() => {
    void refreshDashboard();
    const polling = window.setInterval(() => void refreshDashboard(), 5000);
    return () => window.clearInterval(polling);
  }, []);

  const runAssessment = async () => {
    if (!workspace) return;
    try {
      const assessment = await api<Assessment>(`/api/engagements/${workspace.engagement.id}/assessments`, {
        method: "POST",
        body: JSON.stringify({ requested_by: operator, operator_confirmation: true, profile: "baseline" })
      });
      setNotice(assessment.state === "blocked" ? assessment.block_reason ?? "Assessment was blocked." : "Assessment queued. The workspace will refresh automatically.");
      await refreshDashboard();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not queue assessment.");
    }
  };

  const pauseEngagement = async () => {
    if (!workspace) return;
    try {
      await api<Engagement>(`/api/engagements/${workspace.engagement.id}/pause`, { method: "POST" });
      setNotice("Engagement paused. New assessments are blocked until a new approved engagement is created.");
      await refreshDashboard();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not pause engagement.");
    }
  };

  const cancelAssessment = async (id: string) => {
    try {
      await api<Assessment>(`/api/assessments/${id}/cancel`, { method: "POST" });
      setNotice("Cancellation requested. The bounded collector checks this control between each probe.");
      await refreshDashboard();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not cancel assessment.");
    }
  };

  const reportRows = useMemo(() => workspace?.findings ?? [], [workspace]);

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand">
          <div className="mark"><span>V</span></div>
          <div>
            <p className="eyebrow">Cyber Invasion Army</p>
            <h1>VulnScope</h1>
          </div>
        </div>
        <div className="header-status">
          <span className="pulse" />
          <span>Authorized scope only</span>
          {dashboard?.demo_mode && <Badge value="demo mode" />}
        </div>
      </header>

      <section className="safety-banner">
        <div className="safety-icon">✓</div>
        <div>
          <strong>Engagement-gated assessment</strong>
          <p>Every execution requires written authorization, DNS ownership verification, an active time window, and an operator confirmation. The baseline profile never exploits, guesses passwords, fuzzes, performs denial-of-service testing, or accesses data.</p>
        </div>
      </section>

      {error && <div className="flash flash-error"><strong>Connection or workflow error:</strong> {error}<button onClick={() => setError("")}>Dismiss</button></div>}
      {notice && <div className="flash flash-notice"><span>{notice}</span><button onClick={() => setNotice("")}>Dismiss</button></div>}

      <section className="metrics" aria-label="Assessment program metrics">
        <Metric label="Client engagements" value={dashboard?.counts.engagements ?? "—"} note="authorized records" />
        <Metric label="Ready to assess" value={dashboard?.counts.ready_engagements ?? "—"} note="verified + in window" accent="cyan" />
        <Metric label="Assessment runs" value={dashboard?.counts.assessments ?? "—"} note="bounded baseline only" />
        <Metric label="Open findings" value={dashboard?.counts.open_findings ?? "—"} note="assessor review required" accent="amber" />
      </section>

      <section className="layout-grid">
        <div className="panel engagement-panel">
          <PanelHeading kicker="Control plane" title="Client engagements" description="The evidence collection service only evaluates an explicitly registered target." />
          <EngagementForm
            onCreated={async (engagement) => {
              setNotice("Engagement created. Publish the TXT token, then record verification before running an assessment.");
              await refreshDashboard();
              await selectWorkspace(engagement.id, false);
            }}
            onError={setError}
          />
          <div className="engagement-list">
            {loading && <p className="muted">Loading controlled engagements…</p>}
            {dashboard?.engagements.map((engagement) => (
              <button className={`engagement-row ${workspace?.engagement.id === engagement.id ? "selected" : ""}`} key={engagement.id} onClick={() => void selectWorkspace(engagement.id)}>
                <span className="host-dot" />
                <span className="engagement-copy"><strong>{engagement.target_host}</strong><small>{engagement.client_name} · {engagement.authorization_reference}</small></span>
                <Badge value={engagement.state} />
              </button>
            ))}
          </div>
        </div>

        <div className="panel workspace-panel">
          {!workspace ? <EmptyWorkspace /> : <WorkspaceView workspace={workspace} operator={operator} setOperator={setOperator} onRun={runAssessment} onPause={pauseEngagement} onCancel={cancelAssessment} onRefresh={refreshDashboard} />}
        </div>
      </section>

      <section className="report-panel panel">
        <PanelHeading kicker="Reporting workspace" title="Risk findings & remediation" description="Every result is evidence-led and needs assessor validation before it becomes a client conclusion." />
        {reportRows.length === 0 ? <p className="muted">Select an engagement with a completed assessment to review its findings.</p> : <FindingsTable findings={reportRows} />}
      </section>

      <section className="guardrail-grid">
        <div className="guardrail-card"><span className="guardrail-label">Profile</span><strong>Baseline evidence collection</strong><p>HTTPS metadata, DNS records, headers, cookie flags, `security.txt`, response-header clues, and only ports 80, 443, and 8443.</p></div>
        <div className="guardrail-card"><span className="guardrail-label">Human review</span><strong>OWASP Top 10:2025 workspace</strong><p>Scope-approved manual tasks complement the bounded checks. All findings carry a category, evidence, confidence level, and remediation.</p></div>
        <div className="guardrail-card"><span className="guardrail-label">Stop controls</span><strong>Pause & cancellation trace</strong><p>Pause blocks new launches. Cancellation is audited and observed between each low-impact probe by the collector.</p></div>
      </section>
    </main>
  );
}

function Metric({ label, value, note, accent }: { label: string; value: number | string; note: string; accent?: string }) {
  return <div className={`metric ${accent ? `metric-${accent}` : ""}`}><span>{label}</span><strong>{value}</strong><small>{note}</small></div>;
}

function PanelHeading({ kicker, title, description }: { kicker: string; title: string; description: string }) {
  return <div className="panel-heading"><div><p className="eyebrow">{kicker}</p><h2>{title}</h2></div><p>{description}</p></div>;
}

function EngagementForm({ onCreated, onError }: { onCreated: (engagement: Engagement) => Promise<void>; onError: (message: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    const data = new FormData(event.currentTarget);
    try {
      const engagement = await api<Engagement>("/api/engagements", {
        method: "POST",
        body: JSON.stringify({
          client_name: data.get("client_name"), target_host: data.get("target_host"), authorization_reference: data.get("authorization_reference"), technical_contact: data.get("technical_contact"),
          window_starts_at: new Date(String(data.get("window_starts_at"))).toISOString(), window_ends_at: new Date(String(data.get("window_ends_at"))).toISOString(),
          written_authorization_confirmed: data.get("authorization") === "on"
        })
      });
      event.currentTarget.reset();
      await onCreated(engagement);
      setExpanded(false);
    } catch (reason) { onError(reason instanceof Error ? reason.message : "Could not create engagement."); }
    finally { setBusy(false); }
  };
  return <div className="intake">
    <button className="button button-primary" onClick={() => setExpanded(!expanded)}>{expanded ? "Close engagement intake" : "Create controlled engagement"}</button>
    {expanded && <form className="intake-form" onSubmit={submit}>
      <label>Client name<input required name="client_name" placeholder="Client legal name" /></label>
      <label>In-scope hostname<input required name="target_host" defaultValue="client-staging.example" placeholder="app.client.example" /></label>
      <label>Authorization reference<input required name="authorization_reference" placeholder="CIIA-2026-001" /></label>
      <label>Technical contact<input required type="email" name="technical_contact" placeholder="security@client.example" /></label>
      <div className="time-grid"><label>Window starts<input required type="datetime-local" name="window_starts_at" defaultValue={defaultStart} /></label><label>Window ends<input required type="datetime-local" name="window_ends_at" defaultValue={defaultEnd} /></label></div>
      <label className="confirm"><input required type="checkbox" name="authorization" /><span>I have a written authorization record and the target is within the approved scope.</span></label>
      <button disabled={busy} className="button button-primary" type="submit">{busy ? "Creating…" : "Record authorization & scope"}</button>
    </form>}
  </div>;
}

function EmptyWorkspace() {
  return <div className="empty-workspace"><div className="empty-mark">⌁</div><p className="eyebrow">Assessment workspace</p><h2>Select a controlled engagement</h2><p>Start with a client record, authorized hostname, assessment window, and domain proof. The workspace will then show its execution gate, evidence history, and OWASP-aligned manual review plan.</p></div>;
}

function WorkspaceView({ workspace, operator, setOperator, onRun, onPause, onCancel, onRefresh }: { workspace: Workspace; operator: string; setOperator: (value: string) => void; onRun: () => Promise<void>; onPause: () => Promise<void>; onCancel: (id: string) => Promise<void>; onRefresh: () => Promise<void> }) {
  const { engagement, assessments, manual_tasks, audit } = workspace;
  const canRun = engagement.state === "ready" && engagement.ownership_verified && engagement.written_authorization_confirmed;
  const verify = async () => {
    try {
      await api<Engagement>(`/api/engagements/${engagement.id}/verify`, { method: "POST", body: JSON.stringify({ operator, demo_proof: true }) });
      await onRefresh();
    } catch { await onRefresh(); }
  };
  return <>
    <div className="workspace-title"><div><p className="eyebrow">Active client workspace</p><h2>{engagement.target_host}</h2><p>{engagement.client_name} · {engagement.authorization_reference}</p></div><Badge value={engagement.state} /></div>
    <div className="scope-grid"><ScopeItem label="Authorization" value={engagement.written_authorization_confirmed ? "recorded" : "missing"} valid={engagement.written_authorization_confirmed} /><ScopeItem label="Domain proof" value={engagement.ownership_verified ? "verified" : "waiting"} valid={engagement.ownership_verified} /><ScopeItem label="Approved window" value={`${fmt(engagement.window_starts_at)} — ${fmt(engagement.window_ends_at)}`} valid={engagement.state === "ready"} /></div>
    {!engagement.ownership_verified && <div className="verification-box"><strong>DNS TXT verification required</strong><p>Publish this exact record, then record verification. In demo mode, `.example` targets can use the simulated verification flow.</p><code>{engagement.dns_record_name}  TXT  {engagement.verification_token}</code><button className="button button-secondary" onClick={() => void verify()}>Record DNS verification</button></div>}
    <div className="runbar"><label>Assessor<input value={operator} onChange={(event) => setOperator(event.target.value)} /></label><button className="button button-primary" disabled={!canRun} onClick={() => void onRun()}>Run bounded assessment</button><button className="button button-danger" onClick={() => void onPause()}>Pause engagement</button></div>
    {!canRun && <p className="run-hint">The run control is unavailable until the authorization, DNS proof, and ready-state gates are all satisfied.</p>}
    <div className="subheading"><h3>Assessment activity</h3><span>{assessments.length} recorded</span></div>
    <div className="activity-list">{assessments.length === 0 && <p className="muted">No assessments have been requested for this engagement.</p>}{assessments.map((assessment) => <div className="activity-row" key={assessment.id}><div><Badge value={assessment.state} /><strong>{assessment.profile} evidence collection</strong><small>Requested by {assessment.requested_by} · {fmt(assessment.created_at)}</small>{assessment.block_reason && <em>{assessment.block_reason}</em>}</div>{["queued", "running", "cancel_requested"].includes(assessment.state) && <button className="button button-quiet" onClick={() => void onCancel(assessment.id)}>Cancel</button>}</div>)}</div>
    <div className="subheading"><h3>OWASP assessor plan</h3><span>human-reviewed</span></div>
    <div className="task-grid">{manual_tasks.map((task) => <article key={task.owasp} className="task-card"><span>{task.owasp}</span><h4>{task.title}</h4><p>{task.task}</p></article>)}</div>
    <div className="audit-box"><div className="subheading"><h3>Audit trace</h3><span>{audit.length} events</span></div>{audit.slice(0, 4).map((event) => <div key={event.id} className="audit-row"><span>{fmt(event.created_at)}</span><strong>{event.event_type}</strong><small>{event.actor}</small></div>)}</div>
  </>;
}

function ScopeItem({ label, value, valid }: { label: string; value: string; valid: boolean }) { return <div className="scope-item"><span className={valid ? "status-good" : "status-wait"}>{valid ? "✓" : "○"}</span><div><small>{label}</small><strong>{value}</strong></div></div>; }

function FindingsTable({ findings }: { findings: Finding[] }) {
  return <div className="findings-table"><div className="finding-head"><span>Severity</span><span>Finding</span><span>OWASP</span><span>Recommended next step</span></div>{findings.map((finding) => <article className="finding-row" key={finding.id}><div><SeverityPill value={finding.severity} /><small>{finding.confidence} evidence</small></div><div><strong>{finding.title}</strong><p>{Object.entries(finding.evidence).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : String(value)}`).join(" · ")}</p></div><Badge value={finding.owasp_category} /><div><p>{finding.remediation}</p><small>Assessor verification required before final issue acceptance.</small></div></article>)}</div>;
}
