import type { ScannerName } from "@/api/types";
import { PRIORITIES, SOURCE_LABEL, SOURCE_TYPES } from "@/lib/format";

const SCANNERS: ScannerName[] = ["trivy", "semgrep", "checkov", "gitleaks"];

export interface FilterState {
  priority: string[];
  source_type: string[];
  scanner: string[];
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
  const group = (key: "priority" | "source_type" | "scanner", options: string[], label: (o: string) => string) => (
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
