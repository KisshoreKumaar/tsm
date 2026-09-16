import type { Severity } from "../core/types";

export type RuleStatus = "DRAFT" | "TESTED" | "APPROVED" | "ACTIVE" | "DISABLED" | "RETIRED";
export type RuleAction = "edit" | "backtest" | "approve" | "activate" | "disable" | "retire";

export interface RuleCondition {
  field: string;
  op: string;
  value: string | number | boolean | (string | number)[];
}

export interface RuleThreshold {
  type: "count" | "distinct_count";
  field?: string | null;
  value: number;
}

export interface RuleLogic {
  kinds: string[];
  conditions: RuleCondition[];
  exclusions: RuleCondition[];
  group_by: string[];
  window_seconds: number;
  threshold: RuleThreshold;
  sequence: { kinds: string[]; conditions: RuleCondition[] }[];
}

export interface RuleDefinition {
  name: string;
  description: string;
  severity: Severity;
  confidence: number;
  techniques: string[];
  known_false_positives: string[];
  logic: RuleLogic;
}

export interface RuleSummary {
  id: string;
  name: string;
  status: RuleStatus;
  current_version: number;
  approved_version: number | null;
  active_version: number | null;
  author: string;
  source: "manual" | "ai_draft" | "deterministic_draft";
  source_incident_id: string | null;
  approved_by: string | null;
  approved_at: string | null;
  activated_by: string | null;
  activated_at: string | null;
  created_at: string;
  updated_at: string;
  builtin: boolean;
  allowed_actions: RuleAction[];
}

export interface BacktestResult {
  range: { start: string; end: string };
  events_scanned: number;
  truncated: boolean;
  total_matches: number;
  detections: number;
  incidents_that_would_be_created: number;
  existing_incidents_matched: number;
  matched_incident_ids: string[];
  overlap_with_existing_rules: Record<string, number>;
  matches_in_false_positive_incidents: number;
  matches_in_benign_scenario: number;
  estimated_alerts_per_day: number;
  sample_hits: { summary: string; first_ts: string; last_ts: string; event_ids: string[]; incident_ids: string[] }[];
  runtime_ms: number;
  label: string;
}

export interface RuleVersion {
  version: number;
  definition: RuleDefinition;
  rationale: string | null;
  created_by: string;
  created_at: string;
}

export interface RuleDetail extends RuleSummary {
  definition: RuleDefinition;
  current_version_author: string;
  two_person: boolean;
  sigma_warnings: string[];
  versions: RuleVersion[];
  backtests: { id: string; version: number; created_by: string; created_at: string; result: BacktestResult }[];
}

export interface RuleValidation {
  valid: boolean;
  errors: { loc: string[]; msg: string }[];
  definition: RuleDefinition | null;
  sigma_warnings: string[];
}

export interface RuleDiff {
  rule_id: string;
  from_version: number;
  to_version: number;
  changes: { path: string; change: "added" | "removed" | "changed"; old: unknown; new: unknown }[];
}
