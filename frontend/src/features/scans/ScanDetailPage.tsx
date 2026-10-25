import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiGet } from "@/api/client";
import type { Scan } from "@/api/types";
import { formatDate, isTerminal, PRIORITIES, PRIORITY_COLOR, SOURCE_LABEL, SOURCE_TYPES } from "@/lib/format";
import { FindingsSection } from "@/features/findings/FindingsSection";
import { historyLine, REACH_LABEL } from "@/lib/level2";
import { AttackPathsPanel } from "./AttackPathsPanel";
import { ContextPanel } from "./ContextPanel";
import { ScannerStatusCards } from "./ScannerStatusCards";
import { StatusBadge } from "./StatusBadge";

const STAGES = ["QUEUED", "CLONING", "SCANNING", "ANALYZING"] as const;

export function ScanDetailPage({ scanId }: { scanId: string }) {
  const [focus, setFocus] = useState<{ id: string; n: number } | null>(null);
  const scan = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => apiGet<Scan>(`/scans/${scanId}`),
    refetchInterval: (q) => (isTerminal(q.state.data?.status) ? false : 2000),
  });

  if (scan.isLoading) return <p className="muted">Loading scan…</p>;
  if (scan.isError) return <div className="panel error">{scan.error.message}</div>;
  const s = scan.data!;
  const done = isTerminal(s.status);
  const hasResults = s.summary.findings !== undefined;

  return (
    <>
      <section className="panel">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <div>
            <h1>
              <a href={s.repository.url} target="_blank" rel="noreferrer noopener">
                {s.repository.full_name}
              </a>
            </h1>
            <div className="muted">
              ref <code>{s.requested_ref || "default branch"}</code>
              {s.commit_sha && (
                <>
                  {" "}· commit <code>{s.commit_sha.slice(0, 12)}</code>
                </>
              )}{" "}
              · started {formatDate(s.started_at ?? s.created_at)}
              {s.finished_at && <> · finished {formatDate(s.finished_at)}</>}
              {" "}· <Link to={`/repositories/${s.repository.id}`}>history</Link>
            </div>
            {s.summary.history && (
              <div style={{ marginTop: 4 }}>
                <strong>{historyLine(s.summary.history)}</strong>
                <span className="muted">
                  {s.summary.history.previous_scan_id ? (
                    <>
                      {" "}vs <Link to={`/scans/${s.summary.history.previous_scan_id}`}>previous scan</Link>
                    </>
                  ) : (
                    " · first scan of this ref"
                  )}
                </span>
              </div>
            )}
          </div>
          <StatusBadge status={s.status} />
        </div>
        {!done && (
          <p className="muted">
            {STAGES.map((stage) => (
              <span key={stage} style={{ marginRight: 12, fontWeight: stage === s.status ? 700 : 400 }}>
                {stage === s.status ? "▶ " : ""}
                {stage.toLowerCase()}
              </span>
            ))}
          </p>
        )}
        {s.status_reason && <p className={s.status === "FAILED" ? "error" : "muted"}>{s.status_reason}</p>}
      </section>

      <section className="panel">
        <h2>Scanners</h2>
        <ScannerStatusCards scan={s} />
      </section>

      {hasResults && (
        <section className="panel">
          <h2>Summary</h2>
          <div className="grid tiles">
            <div className="tile">
              <div className="num">{s.summary.findings}</div>
              <div className="muted">findings after merge</div>
            </div>
            <div className="tile">
              <div className="num">{s.summary.raw_findings}</div>
              <div className="muted">raw scanner results</div>
            </div>
            <div className="tile">
              <div className="num">{s.summary.cross_scanner}</div>
              <div className="muted">found by 2+ scanners</div>
            </div>
            {PRIORITIES.map((p) => (
              <div className="tile" key={p}>
                <div className="num" style={{ color: PRIORITY_COLOR[p] }}>
                  {s.summary.by_priority?.[p] ?? 0}
                </div>
                <div className="muted">{p}</div>
              </div>
            ))}
            {SOURCE_TYPES.map((t) => (
              <div className="tile" key={t}>
                <div className="num">{s.summary.by_source_type?.[t] ?? 0}</div>
                <div className="muted">{SOURCE_LABEL[t]}</div>
              </div>
            ))}
          </div>
          {s.summary.intel && (
            <p className="note" style={{ marginTop: 12 }}>
              Threat intel: {s.summary.intel.vulnerabilities} vulnerabilities, {s.summary.intel.epss_scored} with an
              EPSS score, {s.summary.intel.kev_listed} in CISA KEV
              {s.summary.intel.statuses.includes("unavailable") && " (some feeds were unreachable; their factors fell back to CVSS)"}.
            </p>
          )}
        </section>
      )}

      {hasResults && s.summary.context && <ContextPanel context={s.summary.context} />}

      {hasResults && s.summary.reachability && (
        <p className="note">
          Reachability: {s.summary.reachability.status === "ok" ? (
            <>
              {s.summary.reachability.files} source files parsed, {s.summary.reachability.entry_points} entry points
              {" · "}
              {(["L3", "L2", "L1", "L0", "unknown"] as const)
                .map((t) => `${s.summary.reachability?.tiers[t] ?? 0} ${t} (${REACH_LABEL[t]})`)
                .join(" · ")}
            </>
          ) : (
            <>{s.summary.reachability.detail ?? s.summary.reachability.status}; R uses the unknown default</>
          )}
        </p>
      )}

      {done && hasResults && (
        <AttackPathsPanel
          scanId={s.id}
          summary={s.summary}
          onSelectFinding={(id) => setFocus((f) => ({ id, n: (f?.n ?? 0) + 1 }))}
        />
      )}

      {done && hasResults && <FindingsSection scanId={s.id} focus={focus} />}
    </>
  );
}
