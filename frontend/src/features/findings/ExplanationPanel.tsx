import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, apiGet, apiPost } from "@/api/client";
import type { Explanation } from "@/api/types";
import { explanationSource } from "@/lib/level2";

/**
 * Plain-language explanation of the score (blueprint §15). The text is rendered as text:
 * it may quote repository content, so it is never parsed as HTML or Markdown, and its
 * links are not made clickable.
 */
export function ExplanationPanel({ findingId, scanId }: { findingId: string; scanId: string }) {
  const queryClient = useQueryClient();
  const key = ["explanation", findingId, scanId];
  const stored = useQuery({
    queryKey: key,
    queryFn: async () => {
      try {
        return await apiGet<Explanation>(`/findings/${findingId}/explanation?scan_id=${scanId}`);
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) return null; // not generated yet
        throw e;
      }
    },
    retry: false,
  });
  const generate = useMutation({
    mutationFn: (refresh: boolean) =>
      apiPost<Explanation>(
        `/findings/${findingId}/explanation?scan_id=${scanId}${refresh ? "&refresh=true" : ""}`,
        {},
      ),
    onSuccess: (data) => queryClient.setQueryData(key, data),
  });
  const e = stored.data;

  return (
    <div className="tile" style={{ margin: "8px 0" }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <strong>Explanation</strong>
        {e ? (
          <span className="muted" style={{ fontSize: "0.8rem" }}>
            {explanationSource(e)}
          </span>
        ) : null}
      </div>
      {stored.isLoading && <p className="muted">Loading…</p>}
      {stored.isError && <p className="error">{stored.error.message}</p>}
      {e === null && !generate.isPending && (
        <button onClick={() => generate.mutate(false)} style={{ marginTop: 6 }}>
          Explain this score
        </button>
      )}
      {generate.isPending && <p className="muted">Generating (a local model can take up to a minute)…</p>}
      {generate.isError && <p className="error">{generate.error.message}</p>}
      {e && (
        <>
          <p>{e.summary}</p>
          <ul>
            {e.reasons.map((r, i) => (
              <li key={i}>
                {r.claim}{" "}
                {r.evidence.map((ev) => (
                  <span key={ev.id} className="chip" title={ev.label}>
                    {ev.id}
                  </span>
                ))}
              </li>
            ))}
          </ul>
          <p>
            <strong>Impact.</strong> {e.impact}
          </p>
          {e.remediation_steps.length > 0 && (
            <ol>
              {e.remediation_steps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
          )}
          {e.caveats && <p className="muted">{e.caveats}</p>}
          {e.status === "fallback" && (
            <button className="secondary" disabled={generate.isPending} onClick={() => generate.mutate(true)}>
              Try the model again
            </button>
          )}
        </>
      )}
    </div>
  );
}
