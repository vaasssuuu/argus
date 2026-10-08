// Types for the Argus run trace + eval report the dashboard replays.

export type Step = {
  node: string;
  summary: string;
  data: Record<string, unknown>;
  at: string;
};

export type Finding = {
  id: string;
  endpoint: string;
  attacker: string;
  victim: string;
  verdict: "confirmed" | "false_positive";
  checks: string[];
  reason: string;
  request: { method: string; path: string; headers?: Record<string, string> };
  response: { status: number; body_excerpt: string };
  remediation: string | null;
  schema_version: number;
};

export type Trace = {
  run_id: string;
  target: string;
  started: string;
  steps: Step[];
  findings: Finding[];
  schema_version: number;
};

export type Metrics = {
  precision: number;
  recall: number;
  accuracy: number;
  confusion: { TP: number; FP: number; FN: number; TN: number };
  n_cases: number;
};

export type Report = {
  metrics: Metrics;
  per_target?: Record<string, Metrics>;
};

export const isConfirmed = (f: Finding) => f.verdict === "confirmed";

// Strip em/en dashes from any displayed text (trace reasons, model remediation) -> ", ".
export const clean = (s: string) => s.replace(/\s*[—–]\s*/g, ", ");

// The victim's leaked secret, pulled out of a confirmed finding's response for highlighting.
export function leakedSecret(f: Finding): string | null {
  const m = f.response.body_excerpt.match(/"secret"\s*:\s*"([^"]+)"/);
  return m ? m[1] : null;
}

// Group the flat step list into the loop's phases for the timeline.
export function phaseOf(node: string): string {
  if (node === "recon") return "Recon";
  if (node === "candidates") return "Candidates";
  if (node === "poc_synthesis") return "PoC synthesis";
  if (node === "execute") return "Execute";
  if (node === "classify") return "Verdict";
  if (node === "remediate") return "Remediate";
  return node;
}
