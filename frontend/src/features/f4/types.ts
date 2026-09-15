export type PredictionStatus = "WATCHING" | "OBSERVED" | "EXPIRED";

export interface WatchCondition {
  field: string;
  op: string;
  value: string | number | boolean | (string | number)[];
}

export interface WatchSignal {
  description: string;
  kinds: string[];
  conditions: WatchCondition[];
  rule_ids: string[];
  text: string;
}

export interface ScoreFactor {
  name: string;
  label: string;
  points: number;
  max_points: number;
  explanation: string;
}

export interface Prediction {
  id: string;
  incident_id: string;
  technique: { id: string; name: string; tactic: string; url: string };
  label: "HYPOTHESIS";
  score: number;
  band: "LOW" | "MEDIUM" | "HIGH";
  score_label: string;
  factors: ScoreFactor[];
  rationale: string;
  sources: { technique_id: string; technique_name: string; rule_id: string; detection_id: string; weight: number; rationale: string }[];
  evidence_ids: string[];
  watch_signals: WatchSignal[];
  preventive_actions: { text: string; playbook: string | null }[];
  horizon_seconds: number;
  predicted_at: string;
  expires_at: string;
  status: PredictionStatus;
  observed_event_ids: string[];
  observed_at: string | null;
  status_changed_at: string;
  incident_title?: string;
  incident_asset?: string;
}

export interface ExplanationItem {
  prediction_id: string;
  technique_id: string;
  text: string;
  label: "HYPOTHESIS";
  evidence_ids: string[];
  citations_rejected: number;
}

export interface AiCandidate {
  technique_id: string;
  technique_name: string;
  tactics: string[];
  url: string;
  text: string;
  label: "HYPOTHESIS";
  badge: string;
  evidence_ids: string[];
  note: string;
}

export interface Explanation {
  summary: string;
  items: ExplanationItem[];
  ai_candidate: AiCandidate | null;
  candidate_rejected: string | null;
  note: string;
  ai_status: string;
  used_ai: boolean;
  provider: string | null;
  model: string | null;
  incident_revision: number;
  created_at: string;
  stale: boolean;
}

export interface PredictionsResponse {
  incident_id: string;
  label: string;
  hypothesis_note: string;
  predictions: Prediction[];
  explanation: Explanation | null;
  explain_job_id: string | null;
  attack_attribution: string;
}

export interface HitRate {
  observed: number;
  expired: number;
  watching: number;
  total: number;
  hit_rate: number | null;
  resolved_hit_rate: number | null;
  label: string;
}

export interface WatchlistResponse {
  items: Prediction[];
  total: number;
  label: string;
}
