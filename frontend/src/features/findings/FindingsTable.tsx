import type { FindingListItem } from "@/api/types";
import { formatLocation, formatPercent, SOURCE_LABEL } from "@/lib/format";
import { REACH_LABEL, REACH_TONE, STATUS_LABEL } from "@/lib/level2";
import { PriorityBadge, ScoreBar, SeverityText } from "./PriorityBadge";

export type SortKey = "risk" | "score" | "severity" | "title" | "file";

const COLUMNS: { key: SortKey | null; label: string }[] = [
  { key: "risk", label: "Priority" },
  { key: "score", label: "Score" },
  { key: "title", label: "Finding" },
  { key: null, label: "Type" },
  { key: "severity", label: "Severity" },
  { key: "file", label: "Location" },
  { key: null, label: "Reach" },
  { key: null, label: "Detected by" },
];

export function FindingsTable({
  items,
  sort,
  order,
  selected,
  onSort,
  onSelect,
}: {
  items: FindingListItem[];
  sort: SortKey;
  order: "asc" | "desc";
  selected: string | null;
  onSort: (key: SortKey) => void;
  onSelect: (id: string) => void;
}) {
  if (items.length === 0) return <p className="muted">No findings match these filters.</p>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table>
        <thead>
          <tr>
            {COLUMNS.map((c) => (
              <th
                key={c.label}
                className={c.key ? "sortable" : undefined}
                onClick={c.key ? () => onSort(c.key!) : undefined}
                aria-sort={c.key === sort ? (order === "asc" ? "ascending" : "descending") : undefined}
              >
                {c.label}
                {c.key === sort && (order === "asc" ? " ▲" : " ▼")}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {items.map((f) => (
            <tr
              key={f.id}
              className={`clickable ${f.id === selected ? "selected" : ""}`}
              onClick={() => onSelect(f.id)}
            >
              <td>
                <PriorityBadge priority={f.priority} />
              </td>
              <td style={{ minWidth: 110 }}>
                <ScoreBar score={f.score} priority={f.priority} />
              </td>
              <td>
                <div>
                  {f.change !== "existing" && (
                    <span className="badge" style={{ color: "var(--accent)", marginRight: 6 }}>
                      {f.change}
                    </span>
                  )}
                  {f.status !== "open" && (
                    <span className="badge" style={{ color: "var(--muted)", marginRight: 6 }}>
                      {STATUS_LABEL[f.status]}
                    </span>
                  )}
                  {f.title}
                </div>
                <div className="muted mono" style={{ fontSize: "0.75rem" }}>
                  {f.rule_id}
                  {f.kev && <span className="badge" style={{ color: "var(--critical)", marginLeft: 6 }}>KEV</span>}
                  {f.epss !== null && <span style={{ marginLeft: 6 }}>EPSS {formatPercent(f.epss, 2)}</span>}
                </div>
              </td>
              <td>{SOURCE_LABEL[f.source_type]}</td>
              <td>
                <SeverityText severity={f.severity} />
              </td>
              <td className="mono" style={{ wordBreak: "break-all" }}>
                {formatLocation(f.location)}
                {f.location.resource && <div className="muted">{f.location.resource}</div>}
              </td>
              <td>
                {f.reachability && f.reachability !== "n_a" ? (
                  <span
                    className="badge"
                    style={{ color: REACH_TONE[f.reachability] }}
                    title={REACH_LABEL[f.reachability]}
                  >
                    {f.reachability}
                  </span>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
              <td>
                {f.detected_by.map((s) => (
                  <span key={s} className="chip">
                    {s}
                  </span>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
