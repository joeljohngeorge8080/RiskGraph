import type { RunStatus, ScanStatus } from "@/api/types";
import { statusTone } from "@/lib/format";

export function StatusBadge({ status }: { status: ScanStatus | RunStatus }) {
  const tone = statusTone(status);
  return (
    <span className={`badge tone-${tone}`}>
      <span className={`dot bg-${tone}`} />
      {status.replace("_", " ").toLowerCase()}
    </span>
  );
}
