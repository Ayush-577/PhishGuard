export type Severity = "high" | "medium" | "low" | "info";
export type Lever = "urgency" | "fear" | "authority" | "greed" | "curiosity" | "none";
export type Verdict = "low" | "suspicious" | "high";
export type LookupStatus = "ok" | "not_connected" | "could_not_run" | "skipped";

export interface UrlPart {
  protocol: string;
  subdomain: string;
  domain: string;
  path: string;
  query: string;
  fragment: string;
  host: string;
  original: string;
  registrable_domain: string;
  is_ip: boolean;
  uses_https: boolean;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  score_points: number;
  explanation: string;
  lever: Lever;
  category: string;
  evidence: string;
}

export interface ExternalCheck {
  name: string;
  status: LookupStatus;
  source: string;
  checked_at: string | null;
  summary: string;
  details: Record<string, unknown>;
}

export interface AttachmentMeta {
  filename: string;
  content_type: string;
  size_bytes: number | null;
  extension: string;
}

export interface AnalysisReport {
  score: number;
  verdict: Verdict;
  verdict_label: string;
  disclaimer: string;
  findings: Finding[];
  urls: UrlPart[];
  extracted_text: string;
  input_kind: string;
  filename: string | null;
  filesize: number | null;
  upload_deleted: boolean;
  attachments: AttachmentMeta[];
  external_checks: ExternalCheck[];
  what_to_do: string[];
  analyzed_at: string;
}

export interface Sample {
  id: string;
  title: string;
  text: string;
}

export interface QuizQuestion {
  id: string;
  question: string;
  options: string[];
  correct_index: number;
  explanation: string;
  sample: string;
  is_phish: boolean;
}

export interface Explainer {
  title: string;
  sections: { heading: string; body: string; steps?: string[] }[];
}
