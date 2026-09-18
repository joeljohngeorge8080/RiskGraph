import { useQuery } from "@tanstack/react-query";
import { apiGet, type Health, type Readiness, ApiError } from "../api/client";

function StatusRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", gap: 12, padding: "4px 0" }}>
      <span style={{ width: 120, color: "#6b7280" }}>{label}</span>
      <span>{value}</span>
    </div>
  );
}

export function App() {
  const health = useQuery({ queryKey: ["healthz"], queryFn: () => apiGet<Health>("/healthz") });
  const ready = useQuery({
    queryKey: ["readyz"],
    queryFn: () => apiGet<Readiness>("/readyz"),
    refetchInterval: 10_000,
  });

  const readyChecks: Record<string, string> =
    ready.data?.checks ??
    (ready.error instanceof ApiError && ready.error.problem
      ? ((ready.error.problem.checks as Record<string, string> | undefined) ?? {})
      : {});

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", maxWidth: 640, margin: "48px auto" }}>
      <h1 style={{ marginBottom: 4 }}>RiskGraph</h1>
      <p style={{ color: "#6b7280", marginTop: 0 }}>
        Context-aware security risk prioritization. Phase 1 skeleton.
      </p>
      <section>
        <h2 style={{ fontSize: 16 }}>API</h2>
        <StatusRow
          label="healthz"
          value={health.isLoading ? "…" : health.data ? `${health.data.status} (v${health.data.version})` : "unreachable"}
        />
        <StatusRow
          label="readyz"
          value={ready.isLoading ? "…" : ready.data ? ready.data.status : "not ready"}
        />
        {Object.entries(readyChecks).map(([name, value]) => (
          <StatusRow key={name} label={`  ${name}`} value={value} />
        ))}
      </section>
    </main>
  );
}
