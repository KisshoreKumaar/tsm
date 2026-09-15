import type { ClaimLabelName } from "../core/types";

export interface AnswerClaim {
  text: string;
  label: ClaimLabelName;
  evidence_ids: string[];
  citations_rejected: number;
  downgraded: boolean;
}

export interface AnalystAnswer {
  summary: string;
  claims: AnswerClaim[];
  suggested_next_questions: string[];
  suggested_actions: { text: string; playbook: string | null }[];
  confidence: string;
  confidence_note?: string;
  actions_removed?: number;
  question?: string;
  ai_status?: string;
  used_ai?: boolean;
  provider?: string;
  model?: string;
  steps?: number;
  tool_calls?: { step: number; tool: string; ok: boolean }[];
  grounding?: { claims: number; grounded: number; rejected_citations: number };
  injection_suspected?: boolean;
  error?: string | null;
  proposal_ids?: string[];
}

export interface ChatMessageRecord {
  id: string;
  chat_id: string;
  role: "user" | "assistant";
  mode: "quick" | "deep" | "agent";
  content: Record<string, unknown>;
  job_id: string | null;
  status: "pending" | "complete" | "failed";
  actor: string;
  created_at: string;
}

export interface ChatRecord {
  id: string;
  subject_type: "incident" | "campaign" | "global";
  subject_id: string | null;
  title: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  messages?: ChatMessageRecord[];
  quick_prompts: Record<string, string>;
}

export interface PostMessageResult {
  user_message_id: string;
  assistant_message_id: string;
  job_id: string;
  mode: string;
  queue_position: number | null;
  eta_seconds: number | null;
}
