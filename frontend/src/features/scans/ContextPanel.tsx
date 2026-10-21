import type { ScanContext } from "@/api/types";

const MANIFEST_TEXT: Record<ScanContext["manifest"], string> = {
  valid: "Deployment context from",
  absent: "No riskgraph.yaml found: exposure, data, privilege and criticality use the “unknown” defaults.",
  invalid: "riskgraph.yaml was ignored because it is invalid; scores use the “unknown” defaults.",
  unavailable: "The checkout was gone before analysis, so no manifest could be read.",
};

function Value({ v }: { v: string | null }) {
  return v ? <span className="chip">{v.replaceAll("_", " ")}</span> : <span className="muted">unknown</span>;
}

export function ContextPanel({ context }: { context: ScanContext }) {
  return (
    <section className="panel">
      <h2>Context</h2>
      <p className={context.manifest === "invalid" ? "error" : "muted"}>
        {MANIFEST_TEXT[context.manifest]}
        {context.manifest === "valid" && (
          <>
            {" "}
            <code>{context.file}</code>.
          </>
        )}
      </p>
      {context.warnings.length > 0 && (
        <ul className="note">
          {context.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
      {context.services.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Service</th>
              <th>Path</th>
              <th>Exposure</th>
              <th>Privilege</th>
              <th>Data reached</th>
              <th>Criticality</th>
              <th className="score">Findings</th>
            </tr>
          </thead>
          <tbody>
            {context.services.map((s) => (
              <tr key={s.name}>
                <td>
                  <strong>{s.name}</strong>
                </td>
                <td className="mono">{s.path}</td>
                <td>
                  <Value v={s.exposure} />
                </td>
                <td>
                  <Value v={s.privilege} />
                </td>
                <td>
                  <Value v={s.data} />
                </td>
                <td>
                  <Value v={s.criticality} />
                </td>
                <td className="score">{s.findings}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {context.manifest === "valid" && context.unmapped_findings > 0 && (
        <p className="muted">{context.unmapped_findings} finding(s) are outside every service path and use the defaults.</p>
      )}
      {context.public_repository && (
        <p className="note">Committed secrets count as internet-exposed: the repository is public.</p>
      )}
    </section>
  );
}
