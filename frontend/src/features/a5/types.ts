export type SuggestionType = "suppression" | "maintenance_window" | "threshold" | "window" | "dsl_exclusion";
export type SuggestionStatus = "PROPOSED" | "APPROVED" | "REJECTED" | "REVERTED";

export interface EntityScope {
  type: string;
  value: string;
}

export interface MaintenanceSchedule {
  days: number[];
  start: string;
  end: string;
}

export interface TuningScope {
  entities?: EntityScope[];
  schedule?: MaintenanceSchedule | null;
  threshold?: number | null;
  window_seconds?: number | null;
  exclusion?: { field: string; op: string; value: unknown } | null;
  expires_in_days?: number;
}

export interface Impact {
  range: { start: string; end: string };
  events_scanned: number;
  truncated: boolean;
  alerts_before: number;
  alerts_removed: number;
  false_positive_alerts_removed: number;
  true_positive_alerts_removed: number;
  unlinked_alerts_removed: number;
  false_positive_incidents_affected: number;
  true_positive_incidents_affected: string[];
  true_positive_incidents_lost: string[];
  true_positives_lost: number;
  red_flag: boolean;
  sample_removed: { summary: string; first_ts: string; event_ids: string[]; incident_ids: string[] }[];
  label: string;
}

export interface Suggestion {
  id: string;
  type: SuggestionType;
  rule_id: string;
  status: SuggestionStatus;
  scope: TuningScope;
  rationale: string;
  evidence: { closures?: number; false_positive_incidents?: string[]; categories?: Record<string, number>; manual?: boolean };
  impact: Impact | null;
  impact_at: string | null;
  source: "deterministic" | "manual";
  ai_rank: number | null;
  ai_rationale: string | null;
  applied: Record<string, unknown> | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  protected_rule: boolean;
  requires: { protected_rule_acknowledgement: boolean; true_positive_loss_acknowledgement: boolean };
}

export interface ApprovalInput {
  expires_in_days?: number;
  acknowledge_protected_rule: boolean;
  acknowledge_true_positive_loss: boolean;
}

export interface Suppression {
  id: string;
  rule_id: string;
  entities: EntityScope[];
  schedule: MaintenanceSchedule | null;
  reason: string;
  suggestion_id: string | null;
  status: "ACTIVE" | "EXPIRED" | "REVERTED";
  applies: boolean;
  expires_at: string;
  seconds_remaining: number;
  created_by: string;
  created_at: string;
  ended_by: string | null;
  ended_at: string | null;
  end_reason: string | null;
}

export interface ParameterOverride {
  id: string;
  rule_id: string;
  parameters: Record<string, number>;
  previous: Record<string, number>;
  suggestion_id: string | null;
  status: "ACTIVE" | "SUPERSEDED" | "REVERTED";
  created_by: string;
  created_at: string;
  ended_at: string | null;
}

export interface SuppressionsResponse {
  items: Suppression[];
  parameter_overrides: ParameterOverride[];
}

export interface FalsePositiveAnalytics {
  days: number;
  closed_incidents: number;
  false_positive_closures: number;
  false_positive_rate: number | null;
  per_rule: { rule_id: string; incidents: number; false_positives: number; rate: number | null }[];
  per_category: { category: string; count: number }[];
  per_entity: { type: string; value: string; incidents: number; marked_benign: number }[];
  per_source: { source: string; incidents: number; false_positives: number; rate: number | null }[];
  trend: { day: string; false_positives: number }[];
  label: string;
}
