import type { Priority, RunStatus, ScanStatus, Severity, SourceType } from "@/api/types";

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const TERMINAL: ReadonlySet<ScanStatus> = new Set(["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"]);

export function isTerminal(status: ScanStatus | undefined): boolean {
  return status !== undefined && TERMINAL.has(status);
}

export const PRIORITIES: Priority[] = ["critical", "high", "medium", "low"];
export const SOURCE_TYPES: SourceType[] = ["sca", "sast", "secret", "iac", "runtime", "authz"];

export const SOURCE_LABEL: Record<SourceType, string> = {
  sca: "Dependency",
  sast: "Code",
  secret: "Secret",
  iac: "IaC",
  runtime: "Runtime",
  authz: "Access control",
};

export const PRIORITY_COLOR: Record<Priority, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--muted)",
};

export function statusTone(status: ScanStatus | RunStatus): "ok" | "warn" | "bad" | "busy" | "idle" {
  switch (status) {
    case "COMPLETED":
    case "SUCCEEDED":
      return "ok";
    case "PARTIAL":
    case "TIMED_OUT":
      return "warn";
    case "FAILED":
      return "bad";
    case "SKIPPED":
    case "CANCELLED":
    case "PENDING":
    case "QUEUED":
      return "idle";
    default:
      return "busy";
  }
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}

export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export function formatLocation(loc: { file: string; line_start?: number; line_end?: number }): string {
  if (loc.line_start === undefined) return loc.file;
  if (loc.line_end !== undefined && loc.line_end !== loc.line_start) {
    return `${loc.file}:${loc.line_start}-${loc.line_end}`;
  }
  return `${loc.file}:${loc.line_start}`;
}

export function formatPercent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined) return "—";
  return `${(value * 100).toFixed(digits)}%`;
}

/** Build a query string from repeated params, skipping empty values. */
export function buildQuery(params: Record<string, string | number | string[] | undefined | null>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v) => q.append(key, v));
    else q.append(key, String(value));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

/** Same rules as the backend (repositories/service.py) for instant feedback; the API re-checks. */
export function looksLikeGithubUrl(value: string): boolean {
  return /^https:\/\/(www\.)?github\.com\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}?(\.git)?\/?$/.test(
    value.trim(),
  );
}
