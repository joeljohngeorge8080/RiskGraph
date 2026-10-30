import type { FindingChange, ReachabilityTier, ScannerName } from "@/api/types";
import { PRIORITIES, SOURCE_LABEL, SOURCE_TYPES } from "@/lib/format";
import { REACH_LABEL, STATUS_LABEL } from "@/lib/level2";

const SCANNERS: ScannerName[] = ["trivy", "semgrep", "checkov", "gitleaks", "riskgraph"];
const STATUSES = Object.keys(STATUS_LABEL);
const CHANGES: FindingChange[] = ["new", "reopened"];
const TIERS: ReachabilityTier[] = ["L3", "L2", "L1", "L0", "unknown"];

export interface FilterState {
  priority: string[];
  source_type: string[];
  scanner: string[];
  status: string[]; // empty = open only (API default)
  change: string[];
  reachability: string[];
  q: string;
}

function toggle(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

export function FindingFilters({
  value,
  onChange,
}: {
  value: FilterState;
  onChange: (next: FilterState) => void;
}) {
  type GroupKey = "priority" | "source_type" | "scanner" | "status" | "change" | "reachability";
  const group = (key: GroupKey, options: string[], label: (o: string) => string) => (
    <span className="row" style={{ gap: 6 }}>
      {options.map((o) => (
        <label key={o}>
          <input
            type="checkbox"
            checked={value[key].includes(o)}
            onChange={() => onChange({ ...value, [key]: toggle(value[key], o) })}
          />
          {label(o)}
        </label>
      ))}
    </span>
  );

  return (
    <div className="filters" style={{ marginBottom: 10 }}>
      {group("priority", PRIORITIES, (o) => o)}
      <span className="muted">|</span>
      {group("source_type", SOURCE_TYPES, (o) => SOURCE_LABEL[o as keyof typeof SOURCE_LABEL])}
      <span className="muted">|</span>
      {group("scanner", SCANNERS, (o) => o)}
      <span className="muted">|</span>
      {group("reachability", TIERS, (o) => `${o} ${o === "unknown" ? "" : REACH_LABEL[o as ReachabilityTier]}`.trim())}
      <span className="muted">|</span>
      {group("change", CHANGES, (o) => o)}
      <span className="muted">|</span>
      <span className="muted" title="Empty = open findings only">status:</span>
      {group("status", STATUSES, (o) => STATUS_LABEL[o as keyof typeof STATUS_LABEL])}
      <input
        type="text"
        placeholder="search title, file, rule…"
        value={value.q}
        maxLength={100}
        onChange={(e) => onChange({ ...value, q: e.target.value })}
        style={{ minWidth: 220 }}
      />
    </div>
  );
}
