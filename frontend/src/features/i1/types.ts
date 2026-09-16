export type ReportStatus = "DRAFT" | "IN_REVIEW" | "APPROVED" | "MARKED_SUBMITTED";
export type Provenance = "auto" | "ai" | "human" | "profile" | "missing";

export interface DeadlineInfo {
  deadline_utc: string;
  deadline_ist: string;
  window_hours: number;
  seconds_remaining: number;
  overdue: boolean;
  state: "ok" | "warning" | "critical" | "overdue";
  label: string;
}

export interface ReportField {
  id: string;
  label: string;
  value: string;
  provenance: Provenance;
  evidence_ids: string[];
  refs: { type: string; id: string }[];
  note: string | null;
}

export interface Reportability {
  incident_type: string;
  incident_type_label: string;
  reportable: "yes" | "likely" | "unlikely";
  confidence: string;
  score: number;
  reasons: string[];
  category_note: string;
  alternatives: { incident_type: string; label: string; score: number }[];
  notes: string[];
  label: string;
  template_status: string;
}

export interface Completeness {
  required_total: number;
  required_filled: number;
  missing_required: string[];
  automatic_total: number;
  automatic_filled: number;
  ready_for_review: boolean;
}

export interface CertInReport {
  id: string;
  incident_id: string;
  incident_revision: number;
  stale: boolean;
  status: ReportStatus;
  current_version: number;
  version: number;
  detected_at: string;
  deadline: DeadlineInfo;
  fields: ReportField[];
  reportability: Reportability;
  completeness: Completeness;
  template: {
    status: string;
    verified: boolean;
    banner: string | null;
    template_version: string;
    verification_note: string;
    reporting: { authority: string; deadline_hours: number; deadline_basis: string; channels: string[]; note: string };
  };
  ai_status: string | null;
  allowed_actions: string[];
  two_person: boolean;
  never_transmits: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  approved_by: string | null;
  approved_at: string | null;
  submitted_by: string | null;
  submitted_at: string | null;
  submission_reference: string | null;
  submission_note: string | null;
  versions: { version: number; note: string | null; ai_status: string | null; created_by: string; created_at: string }[];
}

export interface DeadlineRow {
  incident_id: string;
  title: string;
  severity: string;
  incident_status: string;
  report_id: string | null;
  report_status: ReportStatus | null;
  deadline: DeadlineInfo;
}

export interface OrgProfile {
  organization_name: string;
  sector: string;
  contact_name: string;
  contact_email: string;
  contact_phone: string;
  address: string | null;
  updated_by: string;
  updated_at: string;
}

export interface ReportDiff {
  report_id: string;
  from_version: number;
  to_version: number;
  changes: { field: string; label: string; old: string; new: string; old_provenance: string; new_provenance: string }[];
}
