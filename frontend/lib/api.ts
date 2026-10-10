export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) { super(message); this.status = status; }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const clean = path.replace(/^\/+/, "");
  const headers = new Headers(init.headers);
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(`/api/backend/${clean}`, {
    ...init,
    headers,
    cache: "no-store",
  });
  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const message = typeof body === "object" && body && "detail" in body ? String(body.detail) : `Request failed (${response.status})`;
    throw new ApiError(message, response.status);
  }
  return body as T;
}

export type Project = { id: string; name: string; description: string; created_at: string };
export type Target = { id: string; project_id: string; name: string; canonical_url: string; is_active: boolean; verification_method: string; verified_at: string | null; created_at: string };
export type Scan = { id: string; project_id: string; target_id: string; status: string; scan_profile: string; progress: number; current_stage: string; error_summary: string | null; scanner_versions?: Record<string, unknown>; created_at: string; started_at: string | null; finished_at: string | null };
export type Finding = { id: string; project_id: string; target_id: string; scan_id: string; rule_id: string; title: string; description: string; severity: string; confidence: string; priority_score: number; verification_status: string; status: string; location: string; recommendation: string; last_seen_at: string };
export type Evidence = { id: string; evidence_type: string; summary: string; sanitized_data: Record<string, unknown>; content_hash: string; created_at: string };
export type FindingDetail = Finding & { evidence: Evidence[]; remediation_template: Record<string, unknown> };
export type Remediation = { id: string; finding_id: string; title: string; rationale: string; patch_diff: string; test_plan: Record<string, unknown>; status: string; created_at: string; reviewed_at: string | null };
