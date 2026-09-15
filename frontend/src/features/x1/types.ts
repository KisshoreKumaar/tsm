export interface ProviderTest {
  ok: boolean;
  provider_id: string;
  model: string;
  tested_at: string;
  json_ok?: boolean;
  latency_ms?: number;
  ttft_ms?: number | null;
  tokens_per_second?: number | null;
  output_tokens?: number;
  finish_reason?: string;
  error?: string;
}

export interface Provider {
  id: string;
  name: string;
  preset: string | null;
  api_type: "ollama" | "openai";
  base_url: string;
  model: string;
  key_set: boolean;
  key_hint: string | null;
  context_tokens: number;
  max_output_tokens: number;
  timeout_seconds: number;
  json_mode: boolean;
  redact: boolean;
  enabled: boolean;
  priority: number;
  is_active: boolean;
  last_test: ProviderTest | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface Preset {
  id: string;
  name: string;
  api_type: "ollama" | "openai";
  base_url: string;
  model: string;
  context_tokens: number;
  max_output_tokens: number;
  timeout_seconds: number;
  requires_key: boolean;
  redact: boolean;
  note: string;
}

export interface ProvidersResponse {
  providers: Provider[];
  env_provider: { id: string; name: string; api_type: string; base_url: string; model: string; key_set: boolean } | null;
  presets: Preset[];
  secret_key_configured: boolean;
  deterministic_only: boolean;
  active: { id: string; name: string; model: string; source: string } | null;
}

export interface AiStatus {
  enabled: boolean;
  mode: "llm" | "deterministic";
  active_provider: { id: string; name: string; model: string; api_type: string; source: string; redact: boolean } | null;
  measured_tokens_per_second: number | null;
  average_latency_ms: number | null;
  queue: { queued: number; running: number };
  calls: number;
  outcomes: Record<string, number>;
  cache_hit_rate: number | null;
  grounding_rate: number | null;
  fallback_count: number;
  injection_detector_pass_rate: number | null;
  notes: string[];
}
