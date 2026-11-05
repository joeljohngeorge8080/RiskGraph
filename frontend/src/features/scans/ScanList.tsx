import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiGet } from "@/api/client";
import type { ScanList as ScanListData } from "@/api/types";
import { formatDate, isTerminal } from "@/lib/format";
import { PriorityCounts } from "@/features/findings/PriorityBadge";
import { StatusBadge } from "./StatusBadge";

export function ScanList() {
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => apiGet<ScanListData>("/scans?limit=25"),
    refetchInterval: (q) => (q.state.data?.items.some((s) => !isTerminal(s.status)) ? 3000 : 15000),
  });

  return (
    <section className="panel">
      <h2>Recent scans</h2>
      {scans.isLoading && <p className="muted">Loading…</p>}
      {scans.isError && <p className="error">{scans.error.message}</p>}
      {scans.data && scans.data.items.length === 0 && <p className="muted">No scans yet.</p>}
      {scans.data && scans.data.items.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Repository</th>
              <th>Ref / commit</th>
              <th>Status</th>
              <th>Findings</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {scans.data.items.map((s) => (
              <tr key={s.id}>
                <td>
                  <Link to={`/scans/${s.id}`}>{s.repository.full_name}</Link>{" "}
                  <Link to={`/repositories/${s.repository.id}`} className="muted" style={{ fontSize: "0.8rem" }}>
                    history
                  </Link>
                </td>
                <td className="mono">
                  {s.requested_ref || "default"}
                  {s.commit_sha && <span className="muted"> @ {s.commit_sha.slice(0, 8)}</span>}
                </td>
                <td>
                  <StatusBadge status={s.status} />
                </td>
                <td>
                  {s.summary.findings !== undefined ? (
                    <PriorityCounts counts={s.summary.by_priority ?? {}} />
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td className="muted">{formatDate(s.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
