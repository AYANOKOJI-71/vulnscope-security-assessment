export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Engagement {
  id: string;
  client_name: string;
  target_host: string;
  authorization_reference: string;
  technical_contact: string;
  window_starts_at: string;
  window_ends_at: string;
  written_authorization_confirmed: boolean;
  verification_token: string;
  dns_record_name: string;
  ownership_verified: boolean;
  state: string;
  created_at: string;
}

export interface Assessment {
  id: string;
  engagement_id: string;
  requested_by: string;
  profile: string;
  state: string;
  started_at?: string;
  completed_at?: string;
  evidence: Record<string, unknown>;
  block_reason?: string;
  created_at: string;
}

export interface Finding {
  id: string;
  assessment_id: string;
  title: string;
  severity: Severity;
  owasp_category: string;
  confidence: string;
  evidence: Record<string, unknown>;
  remediation: string;
  verified: boolean;
}

export interface ManualTask {
  owasp: string;
  title: string;
  task: string;
}

export interface Dashboard {
  demo_mode: boolean;
  guardrails: { allowed_ports: number[]; exclusions: string[] };
  counts: { engagements: number; ready_engagements: number; assessments: number; open_findings: number };
  engagements: Engagement[];
  recent_assessments: Assessment[];
}

export interface Workspace {
  engagement: Engagement;
  assessments: Assessment[];
  findings: Finding[];
  manual_tasks: ManualTask[];
  audit: Array<{ id: string; event_type: string; actor: string; created_at: string; detail: Record<string, unknown> }>;
}

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:4700";

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) }
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { detail?: string };
    throw new Error(body.detail ?? `Request failed with ${response.status}`);
  }
  return response.json() as Promise<T>;
}
