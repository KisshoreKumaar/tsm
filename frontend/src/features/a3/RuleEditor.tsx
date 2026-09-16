import { useState } from "react";
import { useAuth } from "../../core/auth";
import { errorMessage } from "../../core/format";
import type { RuleDefinition, RuleValidation } from "./types";
import "./rules.css";

export const STARTER: RuleDefinition = {
  name: "New detection rule",
  description: "Describe the behaviour this rule detects and when it should fire.",
  severity: "MEDIUM",
  confidence: 60,
  techniques: [],
  known_false_positives: [],
  logic: {
    kinds: ["auth_failure"],
    conditions: [],
    exclusions: [],
    group_by: ["asset", "user"],
    window_seconds: 300,
    threshold: { type: "count", value: 5 },
    sequence: [],
  },
};

export function RuleEditor({
  initial,
  submitLabel,
  onSubmit,
  onCancel,
}: {
  initial?: RuleDefinition | null;
  submitLabel: string;
  onSubmit: (definition: unknown, rationale: string | null) => Promise<void>;
  onCancel?: () => void;
}) {
  const { api } = useAuth();
  const [text, setText] = useState(() => JSON.stringify(initial ?? STARTER, null, 2));
  const [rationale, setRationale] = useState("");
  const [validation, setValidation] = useState<RuleValidation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function parse(): unknown | null {
    try {
      return JSON.parse(text) as unknown;
    } catch (err) {
      setValidation(null);
      setError(`This is not valid JSON: ${(err as Error).message}`);
      return null;
    }
  }

  async function validate() {
    const definition = parse();
    if (definition === null) return;
    setBusy(true);
    setError(null);
    try {
      setValidation(await api.post<RuleValidation>("/rules/validate", { definition }));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function submit() {
    const definition = parse();
    if (definition === null) return;
    setBusy(true);
    setError(null);
    try {
      await onSubmit(definition, rationale.trim() || null);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rule-editor form">
      <label className="field">
        Rule definition (JSON)
        <textarea
          aria-label="Rule definition (JSON)"
          spellCheck={false}
          value={text}
          onChange={(event) => {
            setText(event.target.value);
            setValidation(null);
          }}
        />
      </label>
      <label className="field">
        Why this rule (optional, kept with the version)
        <input value={rationale} maxLength={1000} onChange={(event) => setRationale(event.target.value)} />
      </label>
      <p className="hint">
        Conditions use fields from normalised events with the operators equals, in, contains, startswith, endswith,
        cidr, regex and numeric comparisons. Regular expressions are restricted: no backreferences, lookarounds or
        nested quantifiers.
      </p>
      {validation && validation.valid && (
        <p className="small">
          Valid. {validation.sigma_warnings.length > 0 ? `Sigma export caveat: ${validation.sigma_warnings[0]}` : "Sigma export is straightforward."}
        </p>
      )}
      {validation && !validation.valid && (
        <div className="rule-errors" role="alert">
          {validation.errors.map((item) => (
            <div key={`${item.loc.join(".")}-${item.msg}`}>
              <span className="mono">{item.loc.join(".") || "rule"}</span>: {item.msg}
            </div>
          ))}
        </div>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <div className="form-row">
        <button type="button" className="ghost" onClick={validate} disabled={busy}>
          Validate
        </button>
        <button type="button" onClick={submit} disabled={busy}>
          {busy ? "Saving…" : submitLabel}
        </button>
        {onCancel && (
          <button type="button" className="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
        )}
      </div>
    </div>
  );
}
