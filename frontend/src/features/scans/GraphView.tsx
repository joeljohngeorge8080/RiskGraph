import { useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import { apiGet } from "@/api/client";
import type { AttackPath, GraphData } from "@/api/types";
import { shortLabel } from "@/lib/level2";

const COLORS: Record<string, string> = {
  internet: "#c92a2a",
  service: "#3b5bdb",
  identity: "#e8590c",
  data_store: "#c49000",
  credential: "#ae3ec9",
};

/** Security graph (blueprint §12) drawn with Cytoscape; labels are plain text. */
export function GraphView({ scanId, highlight }: { scanId: string; highlight: AttackPath | null }) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<cytoscape.Core | null>(null);
  const graph = useQuery({
    queryKey: ["graph", scanId],
    queryFn: () => apiGet<GraphData>(`/scans/${scanId}/graph`),
  });

  useEffect(() => {
    if (!ref.current || !graph.data) return;
    const edges = graph.data.edges.filter((e) => e.kind !== "EXPOSES" || !graph.data.edges.some(
      (x) => x.kind === "EXPLOIT" && x.source === e.source && x.target === e.target,
    ));
    const instance = cytoscape({
      container: ref.current,
      elements: [
        ...graph.data.nodes.map((n) => ({
          data: { id: n.key, label: shortLabel(n.label, 24), kind: n.kind },
        })),
        ...edges.map((e, i) => ({
          data: {
            id: `e${i}`,
            source: e.source,
            target: e.target,
            label: e.probability !== null && e.kind !== "RUNS_AS" && e.kind !== "CAN_ACCESS" ? `${e.kind} ${e.probability.toFixed(2)}` : e.kind,
            kind: e.kind,
          },
        })),
      ],
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "background-color": (el: cytoscape.NodeSingular) => COLORS[el.data("kind") as string] ?? "#868e96",
            color: "#868e96",
            "font-size": 10,
            "text-valign": "bottom",
            "text-margin-y": 4,
            width: 22,
            height: 22,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "line-color": "#adb5bd",
            "target-arrow-color": "#adb5bd",
            label: "data(label)",
            "font-size": 8,
            color: "#868e96",
            "text-rotation": "autorotate",
          },
        },
        { selector: 'edge[kind = "EXPLOIT"], edge[kind = "AUTHENTICATES_AS"]', style: { "line-color": "#c92a2a", "target-arrow-color": "#c92a2a", "line-style": "dashed" } },
        { selector: ".hl", style: { "line-color": "#f08c00", "target-arrow-color": "#f08c00", width: 4, "border-width": 3, "border-color": "#f08c00" } },
        { selector: ".dim", style: { opacity: 0.25 } },
      ],
      layout: { name: "breadthfirst", directed: true, roots: ["internet"], spacingFactor: 1.2, padding: 10 },
      userZoomingEnabled: true,
      wheelSensitivity: 0.2,
    });
    cy.current = instance;
    return () => {
      instance.destroy();
      cy.current = null;
    };
  }, [graph.data]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.elements().removeClass("hl dim");
    if (!highlight) return;
    const keys = new Set(highlight.nodes.map((n) => n.key));
    c.elements().addClass("dim");
    c.nodes().filter((n) => keys.has(n.id())).removeClass("dim").addClass("hl");
    for (const e of highlight.edges) {
      c.edges()
        .filter((x) => x.source().id() === e.source && x.target().id() === e.target && x.data("kind") === e.kind)
        .removeClass("dim")
        .addClass("hl");
    }
  }, [highlight, graph.data]);

  if (graph.isError) return <p className="error">{graph.error.message}</p>;
  return (
    <div>
      <div ref={ref} style={{ height: 420, border: "1px solid var(--border)", borderRadius: 8, marginTop: 10 }} />
      <p className="muted" style={{ fontSize: "0.8rem" }}>
        {Object.entries(COLORS).map(([k, c]) => (
          <span key={k} style={{ marginRight: 10 }}>
            <span className="dot" style={{ background: c }} />
            {k.replace("_", " ")}
          </span>
        ))}
        {graph.data?.truncated && " · graph truncated to 2,000 nodes"}
      </p>
    </div>
  );
}
