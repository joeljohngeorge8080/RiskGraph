import { useEffect, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { apiGet } from "@/api/client";
import type { FindingList } from "@/api/types";
import { buildQuery } from "@/lib/format";
import { FindingDrawer } from "./FindingDrawer";
import { FindingFilters, type FilterState } from "./FindingFilters";
import { FindingsTable, type SortKey } from "./FindingsTable";

const PAGE = 50;

/** Findings for one scan. Filters, sort, page and selection live in the URL. */
interface ViewState extends FilterState {
  sort: SortKey;
  order: "asc" | "desc";
  page: number;
  finding: string | null;
}

function fromParams(params: URLSearchParams): ViewState {
  return {
    priority: params.getAll("priority"),
    source_type: params.getAll("source_type"),
    scanner: params.getAll("scanner"),
    status: params.getAll("status"),
    change: params.getAll("change"),
    reachability: params.getAll("reachability"),
    q: params.get("q") ?? "",
    sort: (params.get("sort") ?? "risk") as SortKey,
    order: params.get("order") === "asc" ? "asc" : "desc",
    page: Math.max(0, Number(params.get("page") ?? 0) || 0),
    finding: params.get("finding"),
  };
}

function toParams(v: ViewState): URLSearchParams {
  const next = new URLSearchParams();
  v.priority.forEach((x) => next.append("priority", x));
  v.source_type.forEach((x) => next.append("source_type", x));
  v.scanner.forEach((x) => next.append("scanner", x));
  v.status.forEach((x) => next.append("status", x));
  v.change.forEach((x) => next.append("change", x));
  v.reachability.forEach((x) => next.append("reachability", x));
  if (v.q) next.set("q", v.q);
  if (v.sort !== "risk") next.set("sort", v.sort);
  if (v.order !== "desc") next.set("order", v.order);
  if (v.page) next.set("page", String(v.page));
  if (v.finding) next.set("finding", v.finding);
  return next;
}

/** Findings for one scan. View state is local (instant UI) and mirrored into the URL. */
export function FindingsSection({
  scanId,
  focus = null,
}: {
  scanId: string;
  focus?: { id: string; n: number } | null; // open this finding (e.g. from an attack path)
}) {
  const [params, setParams] = useSearchParams();
  const [view, setView] = useState<ViewState>(() => fromParams(params));
  const [focused, setFocused] = useState(focus);
  const { sort, order, page, finding: selected } = view;

  const update = (patch: Partial<ViewState>) => setView({ ...view, ...patch });

  if (focus !== focused) {
    // adjust state during render (React docs: "storing information from previous renders")
    setFocused(focus);
    if (focus) setView({ ...view, finding: focus.id });
  }

  // The URL mirrors the view (shareable links); the view stays the source of truth.
  useEffect(() => {
    setParams(toParams(view), { replace: true });
  }, [view, setParams]);

  const query = buildQuery({
    priority: view.priority,
    source_type: view.source_type,
    scanner: view.scanner,
    status: view.status,
    change: view.change,
    reachability: view.reachability,
    q: view.q.trim(),
    sort,
    order,
    limit: PAGE,
    offset: page * PAGE,
  });

  const findings = useQuery({
    queryKey: ["findings", scanId, query],
    queryFn: () => apiGet<FindingList>(`/scans/${scanId}/findings${query}`),
    placeholderData: keepPreviousData,
  });

  const total = findings.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE));

  return (
    <div className={`layout-split ${selected ? "open" : ""}`}>
      <section className="panel">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2>Prioritized findings</h2>
          <span className="muted">{total} shown after filters</span>
        </div>
        <FindingFilters value={view} onChange={(f) => update({ ...f, page: 0 })} />
        {findings.isError && <p className="error">{findings.error.message}</p>}
        {findings.data && (
          <FindingsTable
            items={findings.data.items}
            sort={sort}
            order={order}
            selected={selected}
            onSort={(key) =>
              update({ sort: key, order: key === sort && order === "desc" ? "asc" : "desc", page: 0 })
            }
            onSelect={(id) => update({ finding: id === selected ? null : id })}
          />
        )}
        {pages > 1 && (
          <div className="row" style={{ marginTop: 10 }}>
            <button className="secondary" disabled={page === 0} onClick={() => update({ page: page - 1 })}>
              ← Prev
            </button>
            <span className="muted">
              page {page + 1} of {pages}
            </span>
            <button
              className="secondary"
              disabled={page + 1 >= pages}
              onClick={() => update({ page: page + 1 })}
            >
              Next →
            </button>
          </div>
        )}
        <p className="note" style={{ marginTop: 12 }}>
          Score = 100 · likelihood · impact · agreement (0–100). This MVP knows nothing yet about how the
          code is deployed (exposure, reachability, data), so those factors use neutral defaults and
          scores stay below ~46. Critical and High are reached through rules: a format-valid live
          credential is always Critical; a CVE in CISA KEV is at least High.
        </p>
      </section>
      {selected && (
        <FindingDrawer findingId={selected} scanId={scanId} onClose={() => update({ finding: null })} />
      )}
    </div>
  );
}
