/** Minimal fetch wrapper. Replaced by an OpenAPI-generated client in Phase 13. */

export const API_BASE = "/api/v1";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly problem: Record<string, unknown> | null,
  ) {
    super(`API error ${status}`);
  }
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    const problem = (await res.json().catch(() => null)) as Record<string, unknown> | null;
    throw new ApiError(res.status, problem);
  }
  return (await res.json()) as T;
}

export interface Health {
  status: string;
  version: string;
}

export interface Readiness {
  status: string;
  checks: Record<string, string>;
}
