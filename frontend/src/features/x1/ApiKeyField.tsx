import { useState, type FormEvent } from "react";
import { errorMessage } from "../../core/format";

/**
 * Write-only API key entry. The value is cleared from component state as soon as it is submitted, never echoed
 * back by the server, and never stored in the browser.
 */
export function ApiKeyField({
  onSubmit,
  label = "API key",
  submitLabel = "Save key",
  disabled = false,
  disabledReason,
}: {
  onSubmit: (apiKey: string) => Promise<void>;
  label?: string;
  submitLabel?: string;
  disabled?: boolean;
  disabledReason?: string;
}) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const apiKey = value.trim();
    setValue("");
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      await onSubmit(apiKey);
      setSaved(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="form-row" onSubmit={submit}>
      <input
        type="password"
        aria-label={label}
        placeholder={disabled ? (disabledReason ?? "Unavailable") : label}
        autoComplete="new-password"
        spellCheck={false}
        value={value}
        disabled={disabled || busy}
        onChange={(event) => setValue(event.target.value)}
      />
      <button type="submit" disabled={disabled || busy || value.trim().length < 8}>
        {busy ? "Saving…" : submitLabel}
      </button>
      {saved && <span className="small muted">Key stored (encrypted). It will not be shown again.</span>}
      {error && (
        <span role="alert" className="error small">
          {error}
        </span>
      )}
    </form>
  );
}
