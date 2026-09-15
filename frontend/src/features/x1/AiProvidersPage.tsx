import { useState, type FormEvent } from "react";
import { useAuth } from "../../core/auth";
import { ConfirmDialog } from "../../core/ConfirmDialog";
import { errorMessage, formatTime } from "../../core/format";
import { Card, ErrorBanner, Loading } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { ApiKeyField } from "./ApiKeyField";
import type { Preset, Provider, ProvidersResponse, ProviderTest } from "./types";
import "../ai.css";

interface FormState {
  preset: string;
  name: string;
  api_type: "ollama" | "openai";
  base_url: string;
  model: string;
  context_tokens: number;
  max_output_tokens: number;
  timeout_seconds: number;
  redact: boolean;
  make_active: boolean;
}

function fromPreset(preset: Preset): FormState {
  return {
    preset: preset.id,
    name: preset.name,
    api_type: preset.api_type,
    base_url: preset.base_url,
    model: preset.model,
    context_tokens: preset.context_tokens,
    max_output_tokens: preset.max_output_tokens,
    timeout_seconds: preset.timeout_seconds,
    redact: preset.redact,
    make_active: true,
  };
}

function TestResult({ result }: { result: ProviderTest }) {
  if (!result.ok) {
    return <span className="error small">Failed: {result.error}</span>;
  }
  return (
    <span className="small">
      OK · first token {result.ttft_ms ?? "?"} ms · total {result.latency_ms} ms
      {result.tokens_per_second ? ` · ${result.tokens_per_second} tok/s` : ""} · JSON {result.json_ok ? "valid" : "invalid"}
    </span>
  );
}

function AddProvider({ data, onDone }: { data: ProvidersResponse; onDone: () => void }) {
  const { api } = useAuth();
  const first = data.presets[0];
  const [form, setForm] = useState<FormState | null>(first ? fromPreset(first) : null);
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (!form) return null;
  const preset = data.presets.find((p) => p.id === form.preset);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!form) return;
    const key = apiKey.trim();
    setApiKey("");
    setBusy(true);
    setError(null);
    try {
      await api.post("/llm/providers", {
        ...form,
        preset: form.preset,
        ...(key ? { api_key: key } : {}),
      });
      onDone();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) => setForm({ ...form, [key]: value });

  return (
    <Card title="Add a provider">
      <form className="form" onSubmit={submit}>
        <label className="field">
          Preset
          <select
            value={form.preset}
            onChange={(e) => {
              const next = data.presets.find((p) => p.id === e.target.value);
              if (next) setForm(fromPreset(next));
            }}
          >
            {data.presets.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        {preset?.note && <p className="hint">{preset.note}</p>}
        <div className="provider-grid">
          <label className="field">
            Name
            <input value={form.name} onChange={(e) => set("name", e.target.value)} />
          </label>
          <label className="field">
            API type
            <select value={form.api_type} onChange={(e) => set("api_type", e.target.value as FormState["api_type"])}>
              <option value="ollama">Ollama native</option>
              <option value="openai">OpenAI-compatible</option>
            </select>
          </label>
          <label className="field">
            Base URL
            <input value={form.base_url} onChange={(e) => set("base_url", e.target.value)} placeholder="https://…" />
          </label>
          <label className="field">
            Model
            <input value={form.model} onChange={(e) => set("model", e.target.value)} />
          </label>
          <label className="field">
            Context tokens
            <input type="number" value={form.context_tokens} onChange={(e) => set("context_tokens", Number(e.target.value))} />
          </label>
          <label className="field">
            Max output tokens
            <input type="number" value={form.max_output_tokens} onChange={(e) => set("max_output_tokens", Number(e.target.value))} />
          </label>
          <label className="field">
            Timeout (s)
            <input type="number" value={form.timeout_seconds} onChange={(e) => set("timeout_seconds", Number(e.target.value))} />
          </label>
          <label className="field">
            API key {preset?.requires_key ? "(required by this provider)" : "(optional)"}
            <input
              type="password"
              aria-label="New provider API key"
              autoComplete="new-password"
              spellCheck={false}
              value={apiKey}
              disabled={!data.secret_key_configured}
              placeholder={data.secret_key_configured ? "Stored encrypted; never shown again" : "Server secret not configured"}
              onChange={(e) => setApiKey(e.target.value)}
            />
          </label>
        </div>
        <label className="check">
          <input type="checkbox" checked={form.redact} onChange={(e) => set("redact", e.target.checked)} /> Redact usernames, emails and IPs before
          sending to this provider
        </label>
        <label className="check">
          <input type="checkbox" checked={form.make_active} onChange={(e) => set("make_active", e.target.checked)} /> Make this the active provider
        </label>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        <div>
          <button type="submit" disabled={busy || !form.base_url || !form.model}>
            {busy ? "Saving…" : "Add provider"}
          </button>
        </div>
      </form>
    </Card>
  );
}

function ProviderRow({ provider, data, onChanged }: { provider: Provider; data: ProvidersResponse; onChanged: () => void }) {
  const { api } = useAuth();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [test, setTest] = useState<ProviderTest | null>(provider.last_test);
  const [confirmDelete, setConfirmDelete] = useState(false);

  async function act(label: string, run: () => Promise<unknown>) {
    setBusy(label);
    setError(null);
    try {
      await run();
      onChanged();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card
      title={
        <>
          {provider.name} {provider.is_active && <span className="badge status-active">active</span>}
          {!provider.enabled && <span className="badge">disabled</span>}
        </>
      }
    >
      <div className="provider-grid small">
        <div>
          <span className="muted">Model</span>
          <div className="mono">{provider.model}</div>
        </div>
        <div>
          <span className="muted">Endpoint</span>
          <div className="mono">
            {provider.api_type} · {provider.base_url}
          </div>
        </div>
        <div>
          <span className="muted">Budget</span>
          <div>
            {provider.context_tokens} ctx / {provider.max_output_tokens} out · {provider.timeout_seconds}s
          </div>
        </div>
        <div>
          <span className="muted">API key</span>
          <div>{provider.key_set ? `stored (${provider.key_hint})` : "none"}</div>
        </div>
        <div>
          <span className="muted">Redaction</span>
          <div>{provider.redact ? "on" : "off"}</div>
        </div>
      </div>
      <ApiKeyField
        submitLabel={provider.key_set ? "Replace key" : "Save key"}
        disabled={!data.secret_key_configured}
        disabledReason="Server secret not configured"
        onSubmit={async (key) => {
          await api.put(`/llm/providers/${provider.id}/key`, { api_key: key });
          onChanged();
        }}
      />
      <div className="form-row">
        <button type="button" className="ghost" disabled={busy !== null} onClick={() => act("test", async () => setTest(await api.post<ProviderTest>(`/llm/providers/${provider.id}/test`, {})))}>
          {busy === "test" ? "Testing… (slow models can take a minute)" : "Test connection"}
        </button>
        {!provider.is_active && provider.enabled && (
          <button type="button" disabled={busy !== null} onClick={() => act("active", () => api.post("/llm/active", { provider_id: provider.id }))}>
            Make active
          </button>
        )}
        <button
          type="button"
          className="ghost"
          disabled={busy !== null}
          onClick={() => act("enabled", () => api.patch(`/llm/providers/${provider.id}`, { enabled: !provider.enabled }))}
        >
          {provider.enabled ? "Disable" : "Enable"}
        </button>
        {provider.key_set && (
          <button type="button" className="ghost" disabled={busy !== null} onClick={() => act("unkey", () => api.delete(`/llm/providers/${provider.id}/key`))}>
            Remove key
          </button>
        )}
        <button type="button" className="danger" disabled={busy !== null} onClick={() => setConfirmDelete(true)}>
          Delete
        </button>
      </div>
      {test && (
        <p>
          <TestResult result={test} /> <span className="muted small">({formatTime(test.tested_at)})</span>
        </p>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {confirmDelete && (
        <ConfirmDialog
          title={`Delete ${provider.name}?`}
          description="The stored key is deleted with the provider. AI tasks fall back to the next provider or to deterministic results."
          confirmLabel="Delete provider"
          danger
          onCancel={() => setConfirmDelete(false)}
          onConfirm={() => {
            setConfirmDelete(false);
            void act("delete", () => api.delete(`/llm/providers/${provider.id}`));
          }}
        />
      )}
    </Card>
  );
}

export function AiProvidersPage() {
  const { api } = useAuth();
  const { data, error, loading, refetch } = useApiQuery<ProvidersResponse>("/llm/providers");
  const [modeError, setModeError] = useState<string | null>(null);

  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBanner error={error} />;

  return (
    <section>
      <h1>AI providers</h1>
      <p className="muted">
        AEGIS works fully without an LLM. Providers add AI polish, analyst answers and agent proposals; every output is validated and humans apply any
        change. API keys are write-only and stored encrypted on the server.
      </p>
      {!data.secret_key_configured && (
        <div className="warning-banner">
          The server has no <code>AEGIS_SECRET_KEY</code>, so API keys cannot be stored here. Providers without keys (such as Ollama) and
          environment-configured keys still work.
        </div>
      )}
      <Card title="Mode">
        <p>
          {data.deterministic_only
            ? "Deterministic mode: no LLM is used."
            : data.active
              ? `Using ${data.active.name} (${data.active.model}) first, then other enabled providers, then deterministic fallbacks.`
              : "No provider is configured; deterministic results are shown."}
        </p>
        <div className="form-row">
          {!data.deterministic_only && (
            <button
              type="button"
              className="ghost"
              onClick={async () => {
                setModeError(null);
                try {
                  await api.post("/llm/active", { provider_id: null });
                  refetch();
                } catch (err) {
                  setModeError(errorMessage(err));
                }
              }}
            >
              Use deterministic mode only
            </button>
          )}
        </div>
        {modeError && <p className="error">{modeError}</p>}
        {data.env_provider && (
          <p className="hint">
            Environment provider: {data.env_provider.name} · {data.env_provider.model} at {data.env_provider.base_url} (read-only; key{" "}
            {data.env_provider.key_set ? "set" : "not set"}).
          </p>
        )}
      </Card>
      {data.providers.map((provider) => (
        <ProviderRow key={provider.id} provider={provider} data={data} onChanged={refetch} />
      ))}
      <AddProvider data={data} onDone={refetch} />
    </section>
  );
}
