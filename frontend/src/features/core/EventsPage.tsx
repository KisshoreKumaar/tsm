import { useState, type ChangeEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../core/api";
import { useAuth } from "../../core/auth";
import { errorMessage, formatTime, shortId } from "../../core/format";
import type { Page } from "../../core/types";
import { Card, EmptyState, ErrorBanner, JsonBlock, Loading, Pagination } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import { MAX_IMPORT_BYTES, parseEventImport } from "./importEvents";
import { eventSummary } from "./IncidentPage";
import type { EventRecord } from "./types";

const LIMIT = 50;

function ImportPanel({ onImported }: { onImported: () => void }) {
  const { api } = useAuth();
  const [text, setText] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);
  const [details, setDetails] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  function loadFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_IMPORT_BYTES) {
      setError("The file is larger than 4 MiB.");
      return;
    }
    void file.text().then(setText);
  }

  async function submit() {
    setBusy(true);
    setError(null);
    setDetails(null);
    setResult(null);
    try {
      const events = parseEventImport(text);
      setResult(await api.post("/events/batch", { events }));
      onImported();
    } catch (err) {
      setError(errorMessage(err));
      if (err instanceof ApiError) setDetails(err.details);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Import events (JSON, JSON array or JSON Lines)">
      <p className="hint">Only synthetic or authorised lab telemetry. A batch is atomic: one invalid event stores nothing.</p>
      <textarea aria-label="Events to import" rows={6} className="mono full" value={text} onChange={(e) => setText(e.target.value)} />
      <div className="form-row">
        <input type="file" accept=".json,.jsonl,application/json" aria-label="Upload file" onChange={loadFile} />
        <button type="button" onClick={submit} disabled={busy || !text.trim()}>
          {busy ? "Importing…" : "Import"}
        </button>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {details !== null && details !== undefined && <JsonBlock value={details} />}
      {result !== null && <JsonBlock value={result} />}
    </Card>
  );
}

export function EventsPage() {
  const { can } = useAuth();
  const [form, setForm] = useState({ q: "", kind: "", asset: "", user: "", injection: "" });
  const [filters, setFilters] = useState(form);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const { data, error, loading, refetch } = useApiQuery<Page<EventRecord>>("/events", { ...filters, offset, limit: LIMIT });
  const { data: kinds } = useApiQuery<{ kinds: { kind: string }[] }>("/event-kinds");
  const { data: detail } = useApiQuery<Record<string, unknown>>(selected ? `/events/${selected}` : null);
  useLiveEvents(["events"], refetch);

  return (
    <section>
      <h1>Events</h1>
      <form
        className="filters"
        onSubmit={(event) => {
          event.preventDefault();
          setOffset(0);
          setFilters(form);
        }}
      >
        <input aria-label="Search events" placeholder="Search text, IP, process, path…" value={form.q} onChange={(e) => setForm({ ...form, q: e.target.value })} />
        <select aria-label="Kind" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
          <option value="">Any kind</option>
          {kinds?.kinds.map((k) => (
            <option key={k.kind} value={k.kind}>
              {k.kind}
            </option>
          ))}
        </select>
        <input aria-label="Asset" placeholder="Asset" value={form.asset} onChange={(e) => setForm({ ...form, asset: e.target.value })} />
        <input aria-label="User" placeholder="User" value={form.user} onChange={(e) => setForm({ ...form, user: e.target.value })} />
        <select aria-label="Injection" value={form.injection} onChange={(e) => setForm({ ...form, injection: e.target.value })}>
          <option value="">Any content</option>
          <option value="true">Injection-flagged only</option>
        </select>
        <button type="submit">Search</button>
      </form>
      <ErrorBanner error={error} />
      {loading && !data && <Loading />}
      {data && data.items.length === 0 && <EmptyState>No events match.</EmptyState>}
      {data && data.items.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Kind</th>
              <th>Asset / user</th>
              <th>Detail</th>
              <th>Incident</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((event) => (
              <tr key={event.id} className={selected === event.id ? "highlight" : undefined} onClick={() => setSelected(event.id)}>
                <td className="small nowrap">{formatTime(event.timestamp)}</td>
                <td className="mono small">
                  {event.kind}
                  {event.injection_suspected && <span className="badge warn">injection</span>}
                </td>
                <td className="small">
                  {event.asset}
                  <div className="muted">{event.user}</div>
                </td>
                <td className="small mono">{eventSummary(event)}</td>
                <td className="small">
                  {event.incident_ids?.map((id) => (
                    <Link key={id} to={`/incidents/${id}`}>
                      {shortId(id)}
                    </Link>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && <Pagination offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />}
      {detail && (
        <Card title="Event detail (normalized, raw and entities)">
          <JsonBlock value={detail} />
        </Card>
      )}
      {can("ingest") && <ImportPanel onImported={refetch} />}
    </section>
  );
}
