import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/api/client";
import type { FindingDetail, RiskFactor } from "@/api/types";
import { formatDate, formatLocation, formatPercent, SOURCE_LABEL } from "@/lib/format";
import { PriorityBadge, ScoreBar, SeverityText } from "./PriorityBadge";

const FACTOR_NAME: Record<string, string> = {
  E: "Exploitability",
  X: "Exposure",
  R: "Reachability",
  T: "Technical impact",
  D: "Data sensitivity",
  P: "Privilege",
  C: "Criticality",
  K: "Scanner agreement",
};

/** Where a context factor came from: the service, or the hop path to a data store. */
function contextOrigin(f: RiskFactor): string | null {
  const path = f.evidence.path;
  if (Array.isArray(path) && path.every((p) => typeof p === "string")) return path.join(" → ");
  const service = f.evidence.service;
  return typeof service === "string" ? `service ${service}` : null;
}

function FactorRow({ f }: { f: RiskFactor }) {
  const origin = contextOrigin(f);
  return (
    <tr style={{ opacity: f.applicable ? 1 : 0.5 }}>
      <td>
        <strong>{f.name}</strong> <span className="muted">{FACTOR_NAME[f.name] ?? ""}</span>
      </td>
      <td className="score">{f.applicable ? f.value.toFixed(2) : "n/a"}</td>
      <td className="mono" style={{ fontSize: "0.75rem" }}>
        {f.raw_value}
        <div className="muted">
          {f.source} · {f.confidence}
          {origin && <> · {origin}</>}
        </div>
      </td>
    </tr>
  );
}

export function FindingDrawer({
  findingId,
  scanId,
  onClose,
}: {
  findingId: string;
  scanId: string;
  onClose: () => void;
}) {
  const detail = useQuery({
    queryKey: ["finding", findingId, scanId],
    queryFn: () => apiGet<FindingDetail>(`/findings/${findingId}?scan_id=${scanId}`),
  });

  return (
    <aside className="panel drawer">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Finding</h2>
        <button className="secondary" onClick={onClose} aria-label="Close details">
          ✕
        </button>
      </div>
      {detail.isLoading && <p className="muted">Loading…</p>}
      {detail.isError && <p className="error">{detail.error.message}</p>}
      {detail.data && <DrawerBody d={detail.data} />}
    </aside>
  );
}

function DrawerBody({ d }: { d: FindingDetail }) {
  const risk = d.risk;
  const groups: [string, RiskFactor[]][] = risk
    ? [
        ["Likelihood (geometric mean)", risk.factors.filter((f) => f.group === "likelihood")],
        ["Impact (mean)", risk.factors.filter((f) => f.group === "impact")],
        ["Adjustment", risk.factors.filter((f) => f.group === "adjustment")],
      ]
    : [];
  return (
    <>
      <h3>{d.title}</h3>
      <div className="row" style={{ marginBottom: 8 }}>
        {risk && <PriorityBadge priority={risk.priority} />}
        <SeverityText severity={d.severity} />
        <span className="chip">{SOURCE_LABEL[d.source_type]}</span>
        <span className="chip">{d.category}</span>
      </div>
      {risk && (
        <>
          <ScoreBar score={risk.score} priority={risk.priority} />
          <p className="muted mono" style={{ fontSize: "0.75rem" }}>
            100 × L {risk.likelihood.toFixed(3)} × I {risk.impact.toFixed(3)} × K {risk.corroboration.toFixed(2)} ={" "}
            {risk.score.toFixed(2)} · model {risk.model_version}
          </p>
          {risk.overrides.map((o) => (
            <p key={o.rule} className="note">
              <strong>{o.effect}</strong>: {o.reason}
            </p>
          ))}
          <table>
            <tbody>
              {groups.map(([label, factors]) => [
                <tr key={label}>
                  <th colSpan={3}>{label}</th>
                </tr>,
                ...factors.map((f) => <FactorRow key={f.name} f={f} />),
              ])}
            </tbody>
          </table>
        </>
      )}

      <h3 style={{ marginTop: 14 }}>Details</h3>
      <dl className="kv">
        <dt>Location</dt>
        <dd className="mono">
          {formatLocation(d.location)}
          {d.location.resource && ` (${d.location.resource})`}
        </dd>
        <dt>Rule</dt>
        <dd className="mono">{d.rule_id}</dd>
        {d.cwe_ids.length > 0 && (
          <>
            <dt>CWE</dt>
            <dd>{d.cwe_ids.join(", ")}</dd>
          </>
        )}
        {d.package && (
          <>
            <dt>Package</dt>
            <dd className="mono">
              {d.package.name} {d.package.version}
              {d.package.fixed_version && <span className="muted"> → fixed in {d.package.fixed_version}</span>}
            </dd>
          </>
        )}
        {d.vulnerability && (
          <>
            <dt>CVSS</dt>
            <dd className="mono">
              {d.vulnerability.cvss_base ?? "—"} ({d.vulnerability.cvss_source ?? "n/a"})
              <div className="muted" style={{ wordBreak: "break-all" }}>{d.vulnerability.cvss_vector}</div>
            </dd>
            <dt>EPSS</dt>
            <dd>
              {formatPercent(d.vulnerability.epss, 2)}
              {d.vulnerability.epss_percentile !== null && (
                <span className="muted"> (percentile {formatPercent(d.vulnerability.epss_percentile, 0)})</span>
              )}
            </dd>
            <dt>CISA KEV</dt>
            <dd>
              {d.vulnerability.kev === null ? "unknown" : d.vulnerability.kev ? `yes, added ${d.vulnerability.kev_added}` : "no"}
            </dd>
          </>
        )}
        <dt>First seen</dt>
        <dd>{formatDate(d.first_seen_at)}</dd>
      </dl>

      {d.remediation && (
        <>
          <h3 style={{ marginTop: 14 }}>Remediation</h3>
          <p style={{ whiteSpace: "pre-wrap" }}>{d.remediation}</p>
        </>
      )}
      {d.description && (
        <>
          <h3>Description</h3>
          <p className="muted" style={{ whiteSpace: "pre-wrap" }}>{d.description}</p>
        </>
      )}

      <h3 style={{ marginTop: 14 }}>Reported by {d.occurrences.length} scanner result(s)</h3>
      <table>
        <tbody>
          {d.occurrences.map((o, i) => (
            <tr key={`${o.scanner}-${o.rule_id}-${i}`}>
              <td>
                <span className="chip">{o.scanner}</span>
              </td>
              <td>
                <div className="mono" style={{ fontSize: "0.75rem" }}>{o.rule_id}</div>
                <div>{o.title}</div>
                <div className="muted mono" style={{ fontSize: "0.75rem" }}>
                  {formatLocation(o.location)} · {o.scanner_severity ?? o.severity}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
