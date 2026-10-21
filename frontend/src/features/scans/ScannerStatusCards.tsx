import { reportUrl } from "@/api/client";
import type { Scan } from "@/api/types";
import { formatBytes, formatDuration } from "@/lib/format";
import { StatusBadge } from "./StatusBadge";

const ROLE: Record<string, string> = {
  trivy: "dependencies · secrets · IaC",
  semgrep: "source code (SAST)",
  checkov: "infrastructure as code",
  gitleaks: "hard-coded secrets",
};

export function ScannerStatusCards({ scan }: { scan: Scan }) {
  return (
    <div className="grid cards">
      {scan.scanner_runs.map((run) => (
        <div key={run.scanner} className="tile">
          <div className="row" style={{ justifyContent: "space-between" }}>
            <strong>{run.scanner}</strong>
            <StatusBadge status={run.status} />
          </div>
          <div className="muted" style={{ fontSize: "0.8rem" }}>
            {ROLE[run.scanner]}
            {run.version && <> · v{run.version}</>}
          </div>
          <div style={{ marginTop: 6, fontSize: "0.85rem" }}>
            {run.raw_findings_count ?? "—"} results · {formatDuration(run.duration_ms)}
          </div>
          {run.report_available && (
            <a href={reportUrl(scan.id, run.scanner)} download style={{ fontSize: "0.8rem" }}>
              raw report ({formatBytes(run.output_bytes)})
            </a>
          )}
          {run.error_excerpt && <pre className="excerpt">{run.error_excerpt}</pre>}
        </div>
      ))}
    </div>
  );
}
