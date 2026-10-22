import { lazy, Suspense, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/api/client";
import type { AttackPath, ScanSummary } from "@/api/types";
import { shortLabel } from "@/lib/level2";

// Cytoscape is large: load it only when the graph is opened.
const GraphView = lazy(() => import("./GraphView").then((m) => ({ default: m.GraphView })));

const KIND_COLOR: Record<string, string> = {
  internet: "var(--critical)",
  service: "var(--accent)",
  identity: "var(--high)",
  data_store: "var(--medium)",
  credential: "var(--critical)",
};

function kindOf(key: string): string {
  return key.split(":")[0] ?? key;
}

/** Ranked attack paths (blueprint §13) with an optional graph view. */
export function AttackPathsPanel({
  scanId,
  summary,
  onSelectFinding,
}: {
  scanId: string;
  summary: ScanSummary;
  onSelectFinding?: (id: string) => void;
}) {
  const [showGraph, setShowGraph] = useState(false);
  const [highlight, setHighlight] = useState<AttackPath | null>(null);
  const paths = useQuery({
    queryKey: ["attack-paths", scanId],
    queryFn: () => apiGet<AttackPath[]>(`/scans/${scanId}/attack-paths`),
  });
  const noManifest = summary.context?.manifest !== "valid";

  return (
    <section className="panel">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Attack paths</h2>
        <button className="secondary" onClick={() => setShowGraph((v) => !v)}>
          {showGraph ? "Hide graph" : "Show graph"}
        </button>
      </div>
      {paths.isError && <p className="error">{paths.error.message}</p>}
      {paths.data && paths.data.length === 0 && (
        <p className="muted">
          {noManifest
            ? "No attack paths: add a riskgraph.yaml (services, identities, data stores) so RiskGraph knows how the code is deployed."
            : "No path from the Internet or a leaked credential reaches a sensitive data store, privileged identity or critical service."}
        </p>
      )}
      {paths.data && paths.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Score</th>
              <th>Path</th>
              <th>Probability</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {paths.data.slice(0, 20).map((p) => (
              <tr
                key={p.id}
                className={`clickable ${highlight?.id === p.id ? "selected" : ""}`}
                onClick={() => {
                  setHighlight(highlight?.id === p.id ? null : p);
                  setShowGraph(true);
                }}
              >
                <td className="score">{p.score.toFixed(1)}</td>
                <td>
                  {p.nodes.map((n, i) => (
                    <span key={n.key}>
                      {i > 0 && <span className="muted"> → </span>}
                      <span className="chip" style={{ color: KIND_COLOR[kindOf(n.key)] }} title={n.key}>
                        {shortLabel(n.label)}
                      </span>
                    </span>
                  ))}
                </td>
                <td className="mono">{p.probability.toFixed(3)}</td>
                <td>
                  {p.finding_ids.slice(0, 3).map((id, i) => (
                    <button
                      key={id}
                      className="secondary"
                      style={{ padding: "0 0.4rem", marginRight: 4 }}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectFinding?.(id);
                      }}
                    >
                      #{i + 1}
                    </button>
                  ))}
                  {p.finding_ids.length > 3 && <span className="muted">+{p.finding_ids.length - 3}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="note" style={{ marginTop: 10 }}>
        Path score = 100 · ∏ edge probabilities · sink impact. Exploit edges use the best reachable finding on a
        service (geomean of exploitability and reachability); findings on a path get their impact raised to the
        path's (factor I*).
      </p>
      {showGraph && (
        <Suspense fallback={<p className="muted">Loading graph…</p>}>
          <GraphView scanId={scanId} highlight={highlight} />
        </Suspense>
      )}
    </section>
  );
}
