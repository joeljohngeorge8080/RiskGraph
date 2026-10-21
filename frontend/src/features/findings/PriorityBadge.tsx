import type { Priority, Severity } from "@/api/types";
import { PRIORITIES, PRIORITY_COLOR, SEVERITY_COLOR } from "@/lib/format";

export function PriorityBadge({ priority }: { priority: Priority }) {
  return (
    <span className="badge" style={{ color: PRIORITY_COLOR[priority] }}>
      {priority}
    </span>
  );
}

export function SeverityText({ severity }: { severity: Severity }) {
  return <span style={{ color: SEVERITY_COLOR[severity], fontWeight: 600 }}>{severity}</span>;
}

export function PriorityCounts({ counts }: { counts: Partial<Record<Priority, number>> }) {
  return (
    <span>
      {PRIORITIES.map((p) => (
        <span key={p} title={p} style={{ color: PRIORITY_COLOR[p], marginRight: 8, fontWeight: 600 }}>
          {counts[p] ?? 0}
          <span className="muted" style={{ fontWeight: 400, marginLeft: 2 }}>
            {p[0]!.toUpperCase()}
          </span>
        </span>
      ))}
    </span>
  );
}

export function ScoreBar({ score, priority }: { score: number; priority: Priority }) {
  return (
    <div className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
      <span className="score">{score.toFixed(1)}</span>
      <div className="bar" style={{ flex: 1 }}>
        <span style={{ width: `${Math.min(100, score)}%`, background: PRIORITY_COLOR[priority] }} />
      </div>
    </div>
  );
}
