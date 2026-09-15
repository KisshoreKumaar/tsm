import type { IncidentSummary, RiskFactor, Severity } from "../core/types";

export interface CampaignSummary {
  id: string;
  status: "ACTIVE" | "MERGED" | "DISSOLVED";
  merged_into: string | null;
  revision: number;
  title: string;
  risk_score: number;
  severity: Severity;
  first_seen: string;
  last_seen: string;
  incident_count: number;
  assets: string[];
  users: string[];
  created_at: string;
  updated_at: string;
}

export interface CorrelationLink {
  id: string;
  incident_a: string;
  incident_b: string;
  link_type: string;
  entity_type: string;
  entity_value: string;
  time_delta_seconds: number;
  strength: number;
  supporting_event_ids: string[];
  reason: string;
  asset_a?: string | null;
  asset_b?: string | null;
  other_incident_id?: string;
  other_asset?: string | null;
}

export interface CampaignTimelineEvent {
  id: string;
  timestamp: string;
  kind: string;
  asset: string;
  user: string;
  source: string;
  details: string | null;
  injection_suspected: boolean;
  incident_id: string;
}

export interface CampaignDetail extends CampaignSummary {
  risk: { score: number; severity: Severity; label: string; factors: RiskFactor[] };
  incidents: IncidentSummary[];
  links: CorrelationLink[];
  timeline: CampaignTimelineEvent[];
  timeline_truncated: boolean;
}

export interface RelatedResponse {
  incident_id: string;
  campaign: CampaignSummary | null;
  links: CorrelationLink[];
  related_incidents: IncidentSummary[];
}
