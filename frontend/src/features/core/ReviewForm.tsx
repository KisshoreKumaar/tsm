import { useMemo, useState, type FormEvent } from "react";
import { useAuth } from "../../core/auth";
import { errorMessage } from "../../core/format";
import type { IncidentDetail } from "./types";

const CATEGORIES = [
  "authorized_scanner",
  "maintenance_window",
  "known_admin_activity",
  "user_error",
  "test_activity",
  "misconfigured_source",
  "other",
];

export function ReviewForm({ incident, onSaved }: { incident: IncidentDetail; onSaved: () => void }) {
  const { api } = useAuth();
  const [status, setStatus] = useState<string>(incident.status === "MERGED" ? "OPEN" : incident.status);
  const [owner, setOwner] = useState(incident.owner ?? "");
  const [note, setNote] = useState("");
  const [category, setCategory] = useState("");
  const [entities, setEntities] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const entityOptions = useMemo(() => {
    const found = new Set<string>();
    for (const event of incident.events) {
      found.add(`asset|${event.asset}`);
      found.add(`user|${event.user}`);
      if (event.source_ip) found.add(`source_ip|${event.source_ip}`);
      if (event.destination_ip) found.add(`destination_ip|${event.destination_ip}`);
      if (event.domain) found.add(`domain|${event.domain}`);
      if (event.file_hash) found.add(`file_hash|${event.file_hash}`);
    }
    return [...found].sort().slice(0, 40);
  }, [incident.events]);

  const closing = (status === "RESOLVED" || status === "FALSE_POSITIVE") && status !== incident.status;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const body: Record<string, unknown> = { revision: incident.revision };
    if (status !== incident.status) body.status = status;
    if (owner !== (incident.owner ?? "")) body.owner = owner;
    if (note.trim()) body.note = note.trim();
    if (status === "FALSE_POSITIVE" && closing) {
      if (category) body.closure_category = category;
      if (entities.length) {
        body.benign_entities = entities.map((item) => {
          const [type, ...rest] = item.split("|");
          return { type, value: rest.join("|") };
        });
      }
    }
    try {
      await api.patch(`/incidents/${incident.id}`, body);
      setNote("");
      setEntities([]);
      onSaved();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (incident.status === "MERGED") {
    return <p className="muted">This incident was merged into {incident.merged_into}; review that incident instead.</p>;
  }

  return (
    <form className="form" onSubmit={submit}>
      <div className="form-row">
        <label className="field">
          Status
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            {["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Owner
          <input value={owner} maxLength={100} onChange={(e) => setOwner(e.target.value)} />
        </label>
      </div>
      {status === "FALSE_POSITIVE" && closing && (
        <>
          <label className="field">
            Reason category (required)
            <select value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">Choose…</option>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {c.replaceAll("_", " ")}
                </option>
              ))}
            </select>
          </label>
          <fieldset className="field">
            <legend>Entities you believe are benign (optional)</legend>
            <div className="checks">
              {entityOptions.map((item) => (
                <label key={item} className="check">
                  <input
                    type="checkbox"
                    checked={entities.includes(item)}
                    onChange={(e) => setEntities((current) => (e.target.checked ? [...current, item] : current.filter((x) => x !== item)))}
                  />
                  <span className="mono small">{item.replace("|", ": ")}</span>
                </label>
              ))}
            </div>
          </fieldset>
        </>
      )}
      <label className="field">
        Note {closing && "(required to close)"}
        <textarea value={note} rows={3} maxLength={4000} onChange={(e) => setNote(e.target.value)} />
      </label>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button type="submit" disabled={busy}>
        {busy ? "Saving…" : "Save review"}
      </button>
      <p className="hint">Any change bumps the incident revision and cancels pending or approved response requests.</p>
    </form>
  );
}
