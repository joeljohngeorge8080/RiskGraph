import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiPatch } from "@/api/client";
import type { FindingDetail, FindingStatus } from "@/api/types";
import { formatDate } from "@/lib/format";
import { STATUS_LABEL, TRIAGE_OPTIONS } from "@/lib/level2";

/** Set a finding's status (false positive, accepted risk, won't fix, reopen). Audited. */
export function TriagePanel({ d }: { d: FindingDetail }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<FindingStatus>(d.status === "fixed" ? "open" : d.status);
  const [reason, setReason] = useState(d.status_reason ?? "");
  const save = useMutation({
    mutationFn: () => apiPatch(`/findings/${d.id}`, { status, reason: reason.trim() || null }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["finding", d.id] });
      void queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });
  const needsReason = status !== "open" && !reason.trim();
  const unchanged = status === d.status && (reason.trim() || null) === (d.status_reason ?? null);

  return (
    <div className="tile" style={{ margin: "8px 0" }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <strong>Triage</strong>
        <span className="muted" style={{ fontSize: "0.8rem" }}>
          status: {STATUS_LABEL[d.status]}
          {d.status_changed_at && <> · {formatDate(d.status_changed_at)}</>}
        </span>
      </div>
      <div className="row" style={{ marginTop: 6 }}>
        <select value={status} onChange={(e) => setStatus(e.target.value as FindingStatus)} aria-label="Status">
          {TRIAGE_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {STATUS_LABEL[s]}
            </option>
          ))}
        </select>
        <input
          type="text"
          placeholder={status === "open" ? "note (optional)" : "reason (required)"}
          value={reason}
          maxLength={500}
          onChange={(e) => setReason(e.target.value)}
          style={{ flex: 1 }}
          aria-label="Reason"
        />
        <button disabled={needsReason || unchanged || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? "Saving…" : "Save"}
        </button>
      </div>
      {save.isError && <p className="error">{save.error.message}</p>}
      {d.status === "fixed" && <p className="muted">Marked fixed by a later scan; it reopens if seen again.</p>}
    </div>
  );
}
