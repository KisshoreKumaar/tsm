export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE" | "MERGED";
export type ClaimLabelName = "FACT" | "INFERENCE" | "HYPOTHESIS" | "UNKNOWN";

export interface IncidentSummary {
  id: string;
  title: string;
  status: IncidentStatus;
  severity: Severity;
  risk_score: number;
  asset: string;
  user: string;
  owner: string | null;
  revision: number;
  event_count: number;
  first_seen: string;
  last_seen: string;
  first_detected_at: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  merged_into: string | null;
  rules: string[];
}

export interface EventRecord {
  id: string;
  event_id: string | null;
  source: string;
  timestamp: string;
  kind: string;
  asset: string;
  user: string;
  source_ip: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  domain: string | null;
  process_name: string | null;
  parent_process: string | null;
  command_line: string | null;
  file_path: string | null;
  file_hash: string | null;
  details: string | null;
  criticality: number;
  privileged: boolean;
  injection_suspected: boolean;
  injection_matches: string[];
  incident_ids?: string[];
}

export interface Detection {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  confidence: number;
  stage: string;
  techniques: string[];
  first_ts: string;
  last_ts: string;
  event_ids: string[];
  summary: string;
  details: Record<string, unknown>;
  status: "ACTIVE" | "SUPPRESSED";
  suppression_id: string | null;
}

export interface RiskFactor {
  name: string;
  label: string;
  points: number;
  max_points: number;
  explanation: string;
}

export interface Claim {
  id: string;
  label: ClaimLabelName;
  text: string;
  evidence_ids: string[];
}

export interface Technique {
  id: string;
  name: string;
  tactics: string[];
  url: string;
  status?: string;
  note?: string;
  evidence_ids?: string[];
}

export interface Stage {
  stage: string;
  is_tactic: boolean;
  first_ts: string;
  last_ts: string;
  rule_ids: string[];
  detection_ids: string[];
  event_ids: string[];
  techniques: Technique[];
  summaries: string[];
}

export interface Analysis {
  stages: Stage[];
  techniques: Technique[];
  claims: Claim[];
  suppressed: { detection_id: string; rule_id: string; suppression_id: string | null; summary: string }[];
  injection: { suspected: boolean; event_ids: string[] };
  sources: string[];
  entities: { source_ips: string[]; destination_ips: string[]; domains: string[] };
  attack_attribution: string;
}

export interface Note {
  id: string;
  incident_id: string;
  author: string;
  kind: "note" | "closure" | "reopen" | "ai_reference";
  text: string;
  ai_job_id: string | null;
  created_at: string;
}

export interface ResponseRecord {
  id: string;
  incident_id: string;
  incident_revision: number;
  asset: string;
  playbook: string;
  playbook_name: string;
  status: "PENDING" | "APPROVED" | "EXECUTED" | "REJECTED" | "CANCELLED" | "EXPIRED";
  rationale: string;
  requested_by: string;
  requested_at: string;
  approved_by: string | null;
  approved_at: string | null;
  expires_at: string | null;
  approval_expired: boolean;
  executed_by: string | null;
  executed_at: string | null;
  closed_by: string | null;
  closed_at: string | null;
  close_reason: string | null;
  result: Record<string, unknown> | null;
  simulated: true;
}

export interface IncidentDetail extends IncidentSummary {
  risk: { score: number; severity: Severity; label: string; factors: RiskFactor[] };
  analysis: Analysis;
  closure_category: string | null;
  closure_entities: { type: string; value: string }[];
  events: EventRecord[];
  detections: Detection[];
  notes: Note[];
  responses: ResponseRecord[];
  merged_incidents: { id: string; title: string; updated_at: string }[];
}

export interface PlaybookInfo {
  playbooks: { id: string; name: string; description: string; simulated: boolean }[];
  confirmation_phrase: string;
  approval_ttl_seconds: number;
  two_person: boolean;
}
