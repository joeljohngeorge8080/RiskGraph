/** Response shapes of the RiskGraph API (mirrors the backend schemas.py modules). */

export type ScanStatus =
  | "PENDING"
  | "QUEUED"
  | "CLONING"
  | "SCANNING"
  | "ANALYZING"
  | "COMPLETED"
  | "PARTIAL"
  | "FAILED"
  | "CANCELLED";
export type RunStatus = "QUEUED" | "RUNNING" | "SUCCEEDED" | "FAILED" | "TIMED_OUT" | "SKIPPED";
export type Priority = "critical" | "high" | "medium" | "low";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type SourceType = "sca" | "sast" | "secret" | "iac" | "runtime" | "authz";
export type ScannerName = "trivy" | "semgrep" | "checkov" | "gitleaks" | "syft" | "riskgraph";
export type FindingStatus = "open" | "fixed" | "false_positive" | "accepted_risk" | "wont_fix";
export type FindingChange = "new" | "existing" | "reopened";
export type ReachabilityTier = "L0" | "L1" | "L2" | "L3" | "unknown" | "n_a";

export interface ScannerRun {
  scanner: ScannerName;
  status: RunStatus;
  version: string | null;
  exit_code: number | null;
  duration_ms: number | null;
  raw_findings_count: number | null;
  output_bytes: number | null;
  error_excerpt: string | null;
  report_available: boolean;
}

export interface ScanSummary {
  raw_findings?: number;
  findings?: number;
  merged_away?: number;
  cross_scanner?: number;
  by_priority?: Partial<Record<Priority, number>>;
  by_source_type?: Partial<Record<SourceType, number>>;
  by_scanner?: Partial<Record<ScannerName, number>>;
  max_score?: number;
  intel?: { vulnerabilities: number; epss_scored: number; kev_listed: number; statuses: string[] };
  context?: ScanContext;
  reachability?: {
    status: "ok" | "failed" | "unavailable";
    detail: string | null;
    files?: number;
    entry_points?: number;
    reachable_files?: number;
    tiers: Partial<Record<ReachabilityTier, number>>;
  };
  graph?: {
    nodes: number;
    edges: number;
    paths: number;
    sinks_reached: number;
    max_path_score: number;
    findings_on_paths: number;
  };
  history?: {
    previous_scan_id: string | null;
    new: number;
    existing: number;
    reopened: number;
    fixed: number;
    by_status: Partial<Record<FindingStatus, number>>;
  };
}

export type ManifestStatus = "absent" | "valid" | "invalid" | "unavailable";

export interface ServiceContext {
  name: string;
  path: string;
  exposure: string | null;
  privilege: string | null;
  data: string | null;
  criticality: string | null;
  findings: number;
}

export interface ScanContext {
  manifest: ManifestStatus;
  file: string | null;
  warnings: string[];
  public_repository: boolean;
  services: ServiceContext[];
  unmapped_findings: number;
  /** Optional: scans analysed before P7 do not have them. */
  iac_services?: { name: string; path: string | null; exposure: string | null; file: string }[];
  kubernetes_workloads?: KubeWorkload[];
}

export interface KubeWorkload {
  name: string;
  file: string;
  exposure: string | null;
  privilege: string | null;
}

export interface Scan {
  id: string;
  repository: { id: string; full_name: string; url: string };
  requested_ref: string;
  commit_sha: string | null;
  status: ScanStatus;
  status_reason: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  risk_model_version: string | null;
  summary: ScanSummary;
  scanner_runs: ScannerRun[];
  deduplicated: boolean;
}

export interface ScanList {
  items: Scan[];
  total: number;
}

export interface FindingLocation {
  file: string;
  line_start?: number;
  line_end?: number;
  resource?: string;
}

export interface PackageInfo {
  name: string;
  version: string;
  purl: string | null;
  ecosystem: string | null;
  fixed_version: string | null;
}

export interface FindingListItem {
  id: string;
  title: string;
  source_type: SourceType;
  category: string;
  severity: Severity;
  priority: Priority;
  score: number;
  detected_by: ScannerName[];
  location: FindingLocation;
  rule_id: string;
  vulnerability_id: string | null;
  package: PackageInfo | null;
  epss: number | null;
  kev: boolean | null;
  status: FindingStatus;
  change: FindingChange;
  reachability: ReachabilityTier | null;
}

export interface FindingList {
  items: FindingListItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface RiskFactor {
  group: "likelihood" | "impact" | "adjustment";
  name: string;
  value: number;
  raw_value: string | null;
  source: string;
  confidence: string;
  applicable: boolean;
  evidence: Record<string, unknown>;
}

export interface RiskScore {
  model_version: string;
  score: number;
  priority: Priority;
  likelihood: number;
  impact: number;
  corroboration: number;
  overrides: { rule: string; effect: string; reason: string }[];
  factors: RiskFactor[];
  effective_impact: number | null;
  computed_at: string;
}

export interface Occurrence {
  scanner: ScannerName;
  rule_id: string;
  title: string;
  severity: Severity;
  scanner_severity: string | null;
  location: FindingLocation;
  evidence: Record<string, unknown>;
}

export interface Vulnerability {
  id: string;
  cvss_vector: string | null;
  cvss_base: number | null;
  cvss_impact: number | null;
  cvss_exploitability: number | null;
  cvss_source: string | null;
  epss: number | null;
  epss_percentile: number | null;
  kev: boolean | null;
  kev_added: string | null;
}

export interface FindingDetail {
  id: string;
  scan_id: string | null;
  title: string;
  description: string | null;
  remediation: string | null;
  source_type: SourceType;
  category: string;
  severity: Severity;
  rule_id: string;
  cwe_ids: string[];
  location: FindingLocation;
  package: PackageInfo | null;
  detected_by: ScannerName[];
  status: FindingStatus;
  status_reason: string | null;
  status_changed_at: string | null;
  change: FindingChange | null;
  first_seen_at: string;
  last_seen_at: string;
  occurrences: Occurrence[];
  risk: RiskScore | null;
  vulnerability: Vulnerability | null;
  reachability: {
    tier: ReachabilityTier;
    confidence: string;
    evidence: {
      importers?: string[];
      chain?: string[];
      reason?: string;
      via?: string;
      searched?: string[];
      /** L3 (call graph): the vulnerable symbol and the function that calls it. */
      symbol?: string;
      function?: string;
      cve?: string;
    };
    analyzer_version: string;
  } | null;
  attack_paths: AttackPath[];
  history: { at: string; actor: string; action: string; before: Record<string, unknown>; after: Record<string, unknown>; reason: string | null }[];
}

export interface AttackPathEdge {
  source: string;
  target: string;
  kind: string;
  p: number;
  findings: string[];
}

export interface AttackPath {
  id: string;
  source: string;
  sink: string;
  rank: number;
  hops: number;
  nodes: { key: string; label: string }[];
  edges: AttackPathEdge[];
  probability: number;
  sink_impact: number;
  score: number;
  finding_ids: string[];
}

export interface GraphData {
  nodes: { key: string; kind: string; label: string; properties: Record<string, unknown> }[];
  edges: { source: string; target: string; kind: string; probability: number | null; finding_ids: string[] }[];
  truncated: boolean;
}

export interface TrendPoint {
  scan_id: string;
  status: ScanStatus;
  requested_ref: string;
  commit_sha: string | null;
  created_at: string;
  findings: number | null;
  by_priority: Partial<Record<Priority, number>>;
  new: number | null;
  fixed: number | null;
  max_score: number | null;
}

export interface RepositorySummary {
  id: string;
  full_name: string;
  url: string;
  scans: number;
  last_scan: TrendPoint | null;
}

export interface RepositoryDetail extends RepositorySummary {
  history: TrendPoint[];
}

/** P12: an evidence-grounded explanation. Plain text only; never rendered as HTML. */
export interface Explanation {
  finding_id: string;
  scan_id: string;
  status: "validated" | "fallback";
  generator: string;
  summary: string;
  reasons: { claim: string; evidence: { id: string; label: string }[] }[];
  impact: string;
  remediation_steps: string[];
  caveats: string;
  evidence_hash: string;
  attempts: number;
  latency_ms: number;
  created_at: string;
}
