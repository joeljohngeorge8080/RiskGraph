import { describe, expect, it } from "vitest";
import {
  buildQuery,
  formatDuration,
  formatLocation,
  isTerminal,
  looksLikeGithubUrl,
  statusTone,
} from "./format";

describe("format helpers", () => {
  it("knows terminal scan states", () => {
    expect(isTerminal("COMPLETED")).toBe(true);
    expect(isTerminal("PARTIAL")).toBe(true);
    expect(isTerminal("SCANNING")).toBe(false);
    expect(isTerminal(undefined)).toBe(false);
  });

  it("builds repeated query params and skips empties", () => {
    expect(buildQuery({ priority: ["critical", "high"], q: "", limit: 50, x: undefined })).toBe(
      "?priority=critical&priority=high&limit=50",
    );
    expect(buildQuery({})).toBe("");
    expect(buildQuery({ q: "a&b=c" })).toBe("?q=a%26b%3Dc");
  });

  it("formats locations and durations", () => {
    expect(formatLocation({ file: "a.py", line_start: 3, line_end: 3 })).toBe("a.py:3");
    expect(formatLocation({ file: "a.tf", line_start: 7, line_end: 10 })).toBe("a.tf:7-10");
    expect(formatLocation({ file: "requirements.txt" })).toBe("requirements.txt");
    expect(formatDuration(450)).toBe("450 ms");
    expect(formatDuration(2500)).toBe("2.5 s");
    expect(formatDuration(null)).toBe("—");
  });

  it("validates GitHub URLs like the API does", () => {
    expect(looksLikeGithubUrl("https://github.com/bridgecrewio/terragoat")).toBe(true);
    expect(looksLikeGithubUrl("https://github.com/a/b.git")).toBe(true);
    expect(looksLikeGithubUrl("http://github.com/a/b")).toBe(false);
    expect(looksLikeGithubUrl("https://github.com.evil.com/a/b")).toBe(false);
    expect(looksLikeGithubUrl("https://github.com/a/b/tree/main")).toBe(false);
  });

  it("maps statuses to tones", () => {
    expect(statusTone("SUCCEEDED")).toBe("ok");
    expect(statusTone("TIMED_OUT")).toBe("warn");
    expect(statusTone("RUNNING")).toBe("busy");
  });
});
