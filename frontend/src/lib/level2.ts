import type { AttackPath, FindingStatus, Priority, ReachabilityTier, TrendPoint } from "@/api/types";

export const STATUS_LABEL: Record<FindingStatus, string> = {
  open: "open",
  fixed: "fixed",
  false_positive: "false positive",
  accepted_risk: "accepted risk",
  wont_fix: "won't fix",
};

/** Statuses a person may set; "fixed" is set by scans. */
export const TRIAGE_OPTIONS: FindingStatus[] = ["open", "false_positive", "accepted_risk", "wont_fix"];

export const REACH_LABEL: Record<ReachabilityTier, string> = {
  L2: "reachable",
  L1: "imported, unreachable",
  L0: "not imported",
  unknown: "unknown",
  n_a: "n/a",
};

export const REACH_TONE: Record<ReachabilityTier, string> = {
  L2: "var(--high)",
  L1: "var(--medium)",
  L0: "var(--low)",
  unknown: "var(--muted)",
  n_a: "var(--muted)",
};

export function pathLabel(path: Pick<AttackPath, "nodes">): string {
  return path.nodes.map((n) => n.label).join(" → ");
}

export function shortLabel(label: string, max = 28): string {
  return label.length <= max ? label : `${label.slice(0, max - 1)}…`;
}

export interface TrendBar {
  scanId: string;
  x: number;
  total: number;
  segments: { priority: Priority; y: number; height: number }[];
}

const ORDER: Priority[] = ["low", "medium", "high", "critical"];

/** Stacked bars (low at the bottom) scaled to `height`, one per scan, oldest first. */
export function trendBars(points: TrendPoint[], height: number, barWidth: number, gap: number): TrendBar[] {
  const totals = points.map((p) => ORDER.reduce((sum, k) => sum + (p.by_priority[k] ?? 0), 0));
  const max = Math.max(1, ...totals);
  return points.map((p, i) => {
    let y = height;
    const segments = ORDER.filter((k) => (p.by_priority[k] ?? 0) > 0).map((k) => {
      const h = ((p.by_priority[k] ?? 0) / max) * height;
      y -= h;
      return { priority: k, y, height: h };
    });
    return { scanId: p.scan_id, x: i * (barWidth + gap), total: totals[i] ?? 0, segments };
  });
}

export function historyLine(h: { new: number; fixed: number; reopened: number } | undefined): string | null {
  if (!h) return null;
  const parts = [`+${h.new} new`, `−${h.fixed} fixed`];
  if (h.reopened) parts.push(`${h.reopened} reopened`);
  return parts.join(" · ");
}
