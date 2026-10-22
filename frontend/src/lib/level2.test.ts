import { describe, expect, it } from "vitest";
import type { TrendPoint } from "@/api/types";
import { historyLine, pathLabel, shortLabel, trendBars } from "./level2";

const point = (id: string, by: TrendPoint["by_priority"]): TrendPoint => ({
  scan_id: id,
  status: "COMPLETED",
  requested_ref: "",
  commit_sha: null,
  created_at: "2026-10-22T00:00:00Z",
  findings: null,
  by_priority: by,
  new: null,
  fixed: null,
  max_score: null,
});

describe("level 2 helpers", () => {
  it("stacks trend bars scaled to the largest scan", () => {
    const bars = trendBars([point("a", { critical: 2, low: 2 }), point("b", { medium: 2 })], 100, 10, 4);
    expect(bars.map((b) => b.total)).toEqual([4, 2]);
    expect(bars[1]!.x).toBe(14);
    const a = bars[0]!.segments;
    expect(a.map((s) => s.priority)).toEqual(["low", "critical"]);
    expect(a[0]).toEqual({ priority: "low", y: 50, height: 50 });
    expect(a[1]).toEqual({ priority: "critical", y: 0, height: 50 });
    expect(bars[1]!.segments[0]!.height).toBe(50);
  });

  it("handles empty scans", () => {
    expect(trendBars([point("a", {})], 100, 10, 4)[0]!.segments).toEqual([]);
  });

  it("formats paths and history", () => {
    expect(pathLabel({ nodes: [{ key: "internet", label: "Internet" }, { key: "s", label: "app" }] })).toBe(
      "Internet → app",
    );
    expect(shortLabel("x".repeat(40), 10)).toBe("xxxxxxxxx…");
    expect(historyLine({ new: 2, fixed: 1, reopened: 0 })).toBe("+2 new · −1 fixed");
    expect(historyLine({ new: 0, fixed: 0, reopened: 3 })).toBe("+0 new · −0 fixed · 3 reopened");
    expect(historyLine(undefined)).toBeNull();
  });
});
