import type { ClaimLabelName } from "../core/types";

export interface StorySentence {
  id: string;
  label: ClaimLabelName;
  text: string;
  evidence_ids: string[];
  basis: "events" | "aegis_records";
  refs: { type: string; id: string }[];
}

export interface StoryStage {
  stage: string;
  is_tactic: boolean;
  first_ts: string;
  last_ts: string;
  rule_ids: string[];
  techniques: { id: string; name: string; url: string }[];
  event_ids: string[];
  sentence: StorySentence;
}

export interface Story {
  subject_type: "incident" | "campaign";
  subject_id: string;
  subject_revision: number;
  title: string;
  generated_at: string;
  source: "deterministic" | "ai_polished";
  badge: string;
  ai_status: string;
  stages: StoryStage[];
  executive: { lines: { key: string; heading: string; sentence: StorySentence }[] };
  analyst: { paragraphs: StorySentence[][]; word_count: number };
  evidence_index: { ref: string; event_id: string; timestamp: string; kind: string; asset: string; source: string }[];
  citations_valid: boolean;
}

export interface StoryResponse {
  story: Story;
  saved: { version: number; subject_revision: number; source: string; ai_status: string; created_by: string; created_at: string } | null;
  stale: boolean;
  current_revision: number;
}
