export interface Proposal {
  id: string;
  chat_id: string | null;
  job_id: string | null;
  action: "incident.update" | "incident.note" | "response.recommend" | "demo.replay" | string;
  target_type: string;
  target_id: string | null;
  target_revision: number | null;
  required_permission: string;
  payload: Record<string, unknown>;
  rationale: string;
  evidence_ids: string[];
  injection_context: boolean;
  status: "PROPOSED" | "APPLIED" | "DISMISSED" | "STALE" | "FAILED";
  result: Record<string, unknown> | null;
  created_by: string;
  created_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
}

export const ACTION_LABELS: Record<string, string> = {
  "incident.update": "Update incident",
  "incident.note": "Add incident note",
  "response.recommend": "Request simulated response",
  "demo.replay": "Replay demo scenario",
};
