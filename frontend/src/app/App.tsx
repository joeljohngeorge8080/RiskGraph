import { useQuery } from "@tanstack/react-query";
import { Link, Route, Routes, useParams } from "react-router-dom";
import { apiGet, type Readiness } from "@/api/client";
import { UUID_RE } from "@/lib/format";
import { NewScanForm } from "@/features/scans/NewScanForm";
import { ScanList } from "@/features/scans/ScanList";
import { ScanDetailPage } from "@/features/scans/ScanDetailPage";
import { RepositoryPage } from "@/features/repositories/RepositoryPage";

function HealthDot() {
  const ready = useQuery({
    queryKey: ["readyz"],
    queryFn: () => apiGet<Readiness>("/readyz"),
    refetchInterval: 15_000,
  });
  const ok = ready.data?.status === "ok";
  return (
    <span className="muted" title={ok ? "API, database and Redis reachable" : "API not ready"}>
      <span className={`dot ${ok ? "bg-ok" : ready.isLoading ? "bg-idle" : "bg-bad"}`} />
      {ok ? "API ready" : ready.isLoading ? "checking…" : "API unavailable"}
    </span>
  );
}

function HomePage() {
  return (
    <>
      <NewScanForm />
      <ScanList />
    </>
  );
}

function ScanRoute() {
  const { id } = useParams();
  if (!id || !UUID_RE.test(id)) {
    return <div className="panel error">That is not a valid scan id.</div>;
  }
  return <ScanDetailPage scanId={id} />;
}

function RepositoryRoute() {
  const { id } = useParams();
  if (!id || !UUID_RE.test(id)) {
    return <div className="panel error">That is not a valid repository id.</div>;
  }
  return <RepositoryPage repositoryId={id} />;
}

export function App() {
  return (
    <>
      <header className="topbar">
        <Link to="/" className="brand">
          RiskGraph<small>scan → normalize → merge → prioritize</small>
        </Link>
        <HealthDot />
      </header>
      <main className="page">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/scans/:id" element={<ScanRoute />} />
          <Route path="/repositories/:id" element={<RepositoryRoute />} />
          <Route path="*" element={<div className="panel">Page not found. <Link to="/">Home</Link></div>} />
        </Routes>
      </main>
    </>
  );
}
