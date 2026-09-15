import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { useAuth } from "../../core/auth";
import { errorMessage, formatTime } from "../../core/format";
import { Card, ClaimLabel, ErrorBanner, KeyValues, Loading, SeverityBadge, StatusBadge, Tabs } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import { enabledIncidentTabs } from "../incidentTabs";
import { ResponsesPanel } from "./ResponsesPanel";
import { ReviewForm } from "./ReviewForm";
import type { EventRecord, IncidentDetail, PlaybookInfo } from "./types";

export function eventSummary(event: EventRecord): string {
  switch (event.kind) {
    case "network_connection":
      return `${event.source_ip ?? "?"} → ${event.destination_ip}:${event.destination_port}`;
    case "process_start":
    case "suspicious_process":
      return event.command_line ?? event.process_name ?? "";
    case "file_change":
      return event.file_path ?? "";
    case "malicious_indicator":
      return [event.destination_ip, event.domain, event.file_hash, event.source_ip].filter(Boolean).join(" ");
    default:
      return event.source_ip ? `from ${event.source_ip}` : "";
  }
}

export function Timeline({ events, highlight }: { events: EventRecord[]; highlight?: Set<string> }) {
  return (
    <table className="table timeline">
      <thead>
        <tr>
          <th>Time</th>
          <th>Kind</th>
          <th>Source</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>
        {events.map((event) => (
          <tr key={event.id} id={`event-${event.id}`} className={highlight?.has(event.id) ? "highlight" : undefined}>
            <td className="small nowrap">{formatTime(event.timestamp)}</td>
            <td className="mono small">{event.kind}</td>
            <td className="small">{event.source}</td>
            <td className="small">
              <span className="mono">{eventSummary(event)}</span>
              {event.injection_suspected && (
                <div className="warn small" title={event.injection_matches.join(", ")}>
                  ⚠ Instruction-like text detected. Shown as data only:
                </div>
              )}
              {event.details && <blockquote className="quoted">{event.details}</blockquote>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RequestResponse({ incident, playbooks, onDone }: { incident: IncidentDetail; playbooks: PlaybookInfo; onDone: () => void }) {
  const { api } = useAuth();
  const [playbook, setPlaybook] = useState(playbooks.playbooks[0]?.id ?? "");
  const [rationale, setRationale] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post("/responses", { incident_id: incident.id, playbook, rationale: rationale.trim(), revision: incident.revision });
      setRationale("");
      onDone();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="form inline-form" onSubmit={submit}>
      <select aria-label="Playbook" value={playbook} onChange={(e) => setPlaybook(e.target.value)}>
        {playbooks.playbooks.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}
          </option>
        ))}
      </select>
      <input aria-label="Rationale" placeholder="Why is this needed?" value={rationale} minLength={3} onChange={(e) => setRationale(e.target.value)} />
      <button type="submit" disabled={busy || rationale.trim().length < 3}>
        Request
      </button>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </form>
  );
}

export function IncidentPage() {
  const { id = "" } = useParams();
  const { can, principal } = useAuth();
  const [tab, setTab] = useState<string>("analysis");
  const [highlight, setHighlight] = useState<Set<string>>(new Set());
  const { data: incident, error, loading, refetch } = useApiQuery<IncidentDetail>(`/incidents/${id}`);
  const { data: playbooks } = useApiQuery<PlaybookInfo>("/playbooks");
  useLiveEvents(["incident", "response"], (message) => {
    const data = message.data as { incident_id?: string; merged?: string[] } | null;
    if (message.event.startsWith("response") || data?.incident_id === id || data?.merged?.includes(id)) {
      refetch();
    }
  });

  if (loading && !incident) {
    return <Loading />;
  }
  if (!incident) {
    return <ErrorBanner error={error ?? new Error("Incident not found")} />;
  }

  const extraTabs = enabledIncidentTabs(principal?.features ?? []);
  const activeExtra = extraTabs.find((item) => item.id === tab);
  const showEvidence = (eventIds: string[]) => {
    setHighlight(new Set(eventIds));
    setTab("timeline");
  };

  return (
    <section>
      <p className="muted small">
        <Link to="/incidents">Incidents</Link> / {incident.id}
      </p>
      <h1>{incident.title}</h1>
      <div className="header-badges">
        <SeverityBadge severity={incident.severity} />
        <span className="badge">Risk {incident.risk_score}/100 (heuristic)</span>
        <StatusBadge status={incident.status} />
        <span className="badge">Revision {incident.revision}</span>
        {incident.analysis.injection.suspected && <span className="badge warn">Prompt-injection text present</span>}
      </div>
      {incident.merged_into && (
        <p className="warn">
          Merged into <Link to={`/incidents/${incident.merged_into}`}>{incident.merged_into}</Link>
        </p>
      )}
      <ErrorBanner error={error} />
      <KeyValues
        items={[
          ["Asset", incident.asset],
          ["User", incident.user],
          ["Owner", incident.owner ?? "Unassigned"],
          ["First evidence", formatTime(incident.first_seen)],
          ["Last evidence", formatTime(incident.last_seen)],
          ["First detected", formatTime(incident.first_detected_at)],
          ["Events", incident.event_count],
        ]}
      />
      <Tabs<string>
        tabs={[
          { id: "analysis", label: "Analysis" },
          ...extraTabs.filter((item) => item.order < 50).map((item) => ({ id: item.id, label: item.label })),
          { id: "timeline", label: `Timeline (${incident.events.length})` },
          { id: "detections", label: `Detections (${incident.detections.length})` },
          { id: "review", label: `Review & notes (${incident.notes.length})` },
          { id: "responses", label: `Responses (${incident.responses.length})` },
          ...extraTabs.filter((item) => item.order >= 50).map((item) => ({ id: item.id, label: item.label })),
        ]}
        active={tab}
        onChange={setTab}
      />

      {activeExtra && <activeExtra.Component incident={incident} onCite={showEvidence} />}

      {tab === "analysis" && (
        <div className="grid-2">
          <Card title="Claims">
            <ul className="claims">
              {incident.analysis.claims.map((claim) => (
                <li key={claim.id}>
                  <ClaimLabel label={claim.label} /> {claim.text}
                  {claim.evidence_ids.length > 0 && (
                    <button type="button" className="link" onClick={() => showEvidence(claim.evidence_ids)}>
                      {claim.evidence_ids.length} evidence event(s)
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </Card>
          <div>
            <Card title="Attack stages (by earliest evidence)">
              <ol className="stages">
                {incident.analysis.stages.map((stage) => (
                  <li key={stage.stage}>
                    <strong>{stage.stage}</strong> <span className="muted small">{formatTime(stage.first_ts)}</span>
                    <div className="small">{stage.summaries.join(" ")}</div>
                    <div className="small">
                      {stage.techniques.map((t) => (
                        <a key={t.id} href={t.url} target="_blank" rel="noreferrer noopener" className="technique">
                          {t.id} {t.name}
                        </a>
                      ))}
                    </div>
                  </li>
                ))}
              </ol>
              <p className="hint">Technique mappings are candidates from rule logic. {incident.analysis.attack_attribution}</p>
            </Card>
            <Card title="Risk factors">
              <table className="table compact">
                <tbody>
                  {incident.risk.factors.map((factor) => (
                    <tr key={factor.name}>
                      <td>{factor.label}</td>
                      <td className="nowrap">
                        {factor.points}/{factor.max_points}
                      </td>
                      <td className="muted small">{factor.explanation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="hint">{incident.risk.label}</p>
            </Card>
          </div>
        </div>
      )}

      {tab === "timeline" && (
        <Card
          title="Timeline"
          actions={
            highlight.size > 0 && (
              <button type="button" className="ghost" onClick={() => setHighlight(new Set())}>
                Clear highlight ({highlight.size})
              </button>
            )
          }
        >
          <Timeline events={incident.events} highlight={highlight} />
        </Card>
      )}

      {tab === "detections" && (
        <Card title="Detections">
          <table className="table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Stage</th>
                <th>Summary</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {incident.detections.map((detection) => (
                <tr key={detection.id}>
                  <td className="mono">
                    {detection.rule_id}
                    <div className="muted small">{detection.techniques.join(", ") || "no technique"}</div>
                  </td>
                  <td>{detection.stage}</td>
                  <td>
                    {detection.summary}
                    <button type="button" className="link" onClick={() => showEvidence(detection.event_ids)}>
                      {detection.event_ids.length} event(s)
                    </button>
                  </td>
                  <td>
                    <StatusBadge status={detection.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {tab === "review" && (
        <div className="grid-2">
          <Card title="Review">
            {can("investigate") ? <ReviewForm key={incident.revision} incident={incident} onSaved={refetch} /> : <p className="muted">Your role cannot change incidents.</p>}
          </Card>
          <Card title="Notes">
            <ul className="notes">
              {incident.notes.map((note) => (
                <li key={note.id}>
                  <div className="small muted">
                    {note.author} · {note.kind} · {formatTime(note.created_at)}
                  </div>
                  <div className="note-text">{note.text}</div>
                </li>
              ))}
              {incident.notes.length === 0 && <li className="muted">No notes yet.</li>}
            </ul>
          </Card>
        </div>
      )}

      {tab === "responses" && (
        <Card title="Simulated response">
          {can("respond.recommend") && playbooks && incident.status !== "MERGED" && (
            <RequestResponse incident={incident} playbooks={playbooks} onDone={refetch} />
          )}
          <ResponsesPanel responses={incident.responses} phrase={playbooks?.confirmation_phrase ?? "APPROVE SIMULATION"} onChanged={refetch} />
        </Card>
      )}
    </section>
  );
}
