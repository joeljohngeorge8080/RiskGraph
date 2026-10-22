import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiGet } from "@/api/client";
import type { RepositoryDetail } from "@/api/types";
import { formatDate, PRIORITY_COLOR } from "@/lib/format";
import { trendBars } from "@/lib/level2";
import { PriorityCounts } from "@/features/findings/PriorityBadge";
import { StatusBadge } from "@/features/scans/StatusBadge";

const H = 140;
const BAR = 22;
const GAP = 8;

/** Scan history of one repository: a stacked priority trend and the scan list. */
export function RepositoryPage({ repositoryId }: { repositoryId: string }) {
  const repo = useQuery({
    queryKey: ["repository", repositoryId],
    queryFn: () => apiGet<RepositoryDetail>(`/repositories/${repositoryId}?history=30`),
  });
  if (repo.isLoading) return <p className="muted">Loading…</p>;
  if (repo.isError) return <div className="panel error">{repo.error.message}</div>;
  const r = repo.data!;
  const done = r.history.filter((p) => p.findings !== null);
  const bars = trendBars(done, H, BAR, GAP);
  const width = Math.max(1, bars.length * (BAR + GAP));

  return (
    <>
      <section className="panel">
        <h1>
          <a href={r.url} target="_blank" rel="noreferrer noopener">
            {r.full_name}
          </a>
        </h1>
        <p className="muted">{r.scans} scan(s)</p>
        {bars.length > 0 ? (
          <svg
            width={width}
            height={H + 18}
            role="img"
            aria-label="Findings per scan by priority"
            style={{ maxWidth: "100%", overflow: "visible" }}
          >
            {bars.map((b, i) => (
              <g key={b.scanId}>
                <title>
                  {`${formatDate(done[i]!.created_at)}: ${b.total} findings` +
                    (done[i]!.new !== null ? `, +${done[i]!.new} new, −${done[i]!.fixed ?? 0} fixed` : "")}
                </title>
                {b.segments.map((s) => (
                  <rect key={s.priority} x={b.x} y={s.y} width={BAR} height={Math.max(1, s.height)} fill={PRIORITY_COLOR[s.priority]} />
                ))}
                <text x={b.x + BAR / 2} y={H + 14} textAnchor="middle" fontSize="10" fill="currentColor">
                  {b.total}
                </text>
              </g>
            ))}
          </svg>
        ) : (
          <p className="muted">No completed scans yet.</p>
        )}
      </section>
      <section className="panel">
        <h2>Scans</h2>
        <table>
          <thead>
            <tr>
              <th>Started</th>
              <th>Ref / commit</th>
              <th>Status</th>
              <th>Findings</th>
              <th>Change</th>
              <th>Max score</th>
            </tr>
          </thead>
          <tbody>
            {[...r.history].reverse().map((p) => (
              <tr key={p.scan_id}>
                <td>
                  <Link to={`/scans/${p.scan_id}`}>{formatDate(p.created_at)}</Link>
                </td>
                <td className="mono">
                  {p.requested_ref || "default"}
                  {p.commit_sha && <span className="muted"> @ {p.commit_sha.slice(0, 8)}</span>}
                </td>
                <td>
                  <StatusBadge status={p.status} />
                </td>
                <td>{p.findings !== null ? <PriorityCounts counts={p.by_priority} /> : <span className="muted">—</span>}</td>
                <td>{p.new !== null ? `+${p.new} / −${p.fixed ?? 0}` : "—"}</td>
                <td className="score">{p.max_score !== null ? p.max_score.toFixed(1) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
