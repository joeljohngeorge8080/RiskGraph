/** Minimal fetch wrapper. Replaced by an OpenAPI-generated client in Phase 13. */

export const API_BASE = "/api/v1";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly problem: Record<string, unknown> | null,
  ) {
    super(problemMessage(status, problem));
  }
}

/** Human-readable message from an RFC 7807 problem body. */
export function problemMessage(status: number, problem: Record<string, unknown> | null): string {
  const detail = problem?.["detail"];
  const title = problem?.["title"];
  if (typeof detail === "string" && detail) return detail;
  if (typeof title === "string" && title) return title;
  return `Request failed (HTTP ${status})`;
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const problem = (await res.json().catch(() => null)) as Record<string, unknown> | null;
    throw new ApiError(res.status, problem);
  }
  return (await res.json()) as T;
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: { Accept: "application/json" } });
  return handle<T>(res);
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return handle<T>(res);
}

export async function apiPatch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "PATCH",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return handle<T>(res);
}

export function reportUrl(scanId: string, scanner: string): string {
  return `${API_BASE}/scans/${encodeURIComponent(scanId)}/reports/${encodeURIComponent(scanner)}`;
}

export interface Health {
  status: string;
  version: string;
}

export interface Readiness {
  status: string;
  checks: Record<string, string>;
}
