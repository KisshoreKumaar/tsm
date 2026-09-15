import { useState } from "react";
import { useAuth } from "../../core/auth";
import { errorMessage, formatTime } from "../../core/format";
import { Card, ClaimLabel, EmptyState, ErrorBanner, Loading } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import type { IncidentTabProps } from "../core/incidentTabTypes";
import { LIKELIHOOD_HINT, PredictionCard } from "./PredictionCard";
import type { Explanation, Prediction, PredictionsResponse } from "./types";
import "./prediction.css";

function ExplanationCard({ explanation, onCite }: { explanation: Explanation; onCite: (eventIds: string[]) => void }) {
  const candidate = explanation.ai_candidate;
  return (
    <Card title="Explanation">
      <div className="header-badges">
        <span className="badge">{explanation.used_ai ? `AI (${explanation.ai_status})` : "Deterministic"}</span>
        {explanation.used_ai && explanation.model && <span className="badge">{explanation.model}</span>}
        {explanation.stale && <span className="badge warn">incident changed since revision {explanation.incident_revision}</span>}
        <span className="muted small">{formatTime(explanation.created_at)}</span>
      </div>
      <p>{explanation.summary}</p>
      {candidate && (
        <div className="small">
          <span className="badge warn">{candidate.badge}</span> <ClaimLabel label={candidate.label} />{" "}
          <a className="technique" href={candidate.url} target="_blank" rel="noreferrer noopener">
            {candidate.technique_id} {candidate.technique_name}
          </a>{" "}
          {candidate.text}{" "}
          <button type="button" className="link" onClick={() => onCite(candidate.evidence_ids)}>
            cited evidence ({candidate.evidence_ids.length})
          </button>
          <div className="hint">{candidate.note}</div>
        </div>
      )}
      {explanation.candidate_rejected && <p className="hint">An AI candidate was rejected: {explanation.candidate_rejected}.</p>}
      <p className="hint">{explanation.note}</p>
    </Card>
  );
}

interface Marker {
  key: string;
  at: string;
  kind: "predicted" | "observed";
  text: string;
  eventIds: string[];
}

function PredictionTimeline({ predictions, onCite }: { predictions: Prediction[]; onCite: (eventIds: string[]) => void }) {
  const markers: Marker[] = predictions
    .flatMap((p): Marker[] => [
      { key: `${p.id}-predicted`, at: p.predicted_at, kind: "predicted", text: `Predicted ${p.technique.id} ${p.technique.name}`, eventIds: p.evidence_ids },
      ...(p.observed_at
        ? [{ key: `${p.id}-observed`, at: p.observed_at, kind: "observed" as const, text: `Observed ${p.technique.id} ${p.technique.name}`, eventIds: p.observed_event_ids }]
        : []),
    ])
    .sort((a, b) => a.at.localeCompare(b.at) || a.key.localeCompare(b.key));
  return (
    <Card title="Prediction timeline">
      <ol className="prediction-timeline">
        {markers.map((marker) => (
          <li key={marker.key}>
            <span className="muted">{formatTime(marker.at)}</span>
            <span className={`marker-${marker.kind}`}>
              {marker.text}{" "}
              <button type="button" className="link" onClick={() => onCite(marker.eventIds)}>
                evidence
              </button>
            </span>
          </li>
        ))}
      </ol>
    </Card>
  );
}

export function PredictionsTab({ incident, onCite }: IncidentTabProps) {
  const { api, can } = useAuth();
  const { data, error, loading, refetch } = useApiQuery<PredictionsResponse>(`/incidents/${incident.id}/predictions`, {
    revision: incident.revision,
  });
  const [requested, setRequested] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [alert, setAlert] = useState<string | null>(null);

  useLiveEvents(["prediction"], (message) => {
    const payload = message.data as { incident_id?: string; technique_id?: string } | null;
    if (payload?.incident_id !== incident.id) return;
    if (message.event === "prediction.observed" && payload.technique_id) {
      setAlert(`Prediction observed: ${payload.technique_id}. The incident risk score was recalculated.`);
    }
    if (message.event === "prediction.explained") setRequested(false);
    refetch();
  });

  async function explain() {
    setActionError(null);
    try {
      await api.post(`/incidents/${incident.id}/predictions/explain`, {});
      setRequested(true);
      refetch();
    } catch (err) {
      setActionError(errorMessage(err));
    }
  }

  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBanner error={error} />;
  const explanations = new Map((data.explanation?.items ?? []).map((item) => [item.prediction_id, item]));
  const pending = requested || data.explain_job_id !== null;

  return (
    <div>
      {alert && (
        <div className="danger-banner" role="status">
          {alert}{" "}
          <button type="button" className="link" onClick={() => setAlert(null)}>
            dismiss
          </button>
        </div>
      )}
      <Card
        title="What's likely next"
        actions={
          can("ai.use") &&
          data.predictions.length > 0 && (
            <button type="button" className="ghost" onClick={explain} disabled={pending}>
              {pending ? "Explaining… (about a minute on the self-hosted model)" : "Explain"}
            </button>
          )
        }
      >
        <p className="hint">
          {data.hypothesis_note} {LIKELIHOOD_HINT}
        </p>
        {actionError && (
          <p role="alert" className="error">
            {actionError}
          </p>
        )}
        {data.predictions.length === 0 ? (
          <EmptyState>No next-step predictions: the curated model has no transitions from this incident&apos;s observed techniques.</EmptyState>
        ) : (
          <div className="prediction-list">
            {data.predictions.map((prediction, index) => (
              <PredictionCard key={prediction.id} prediction={prediction} rank={index + 1} onCite={onCite} explanation={explanations.get(prediction.id)} />
            ))}
          </div>
        )}
        <p className="hint">{data.attack_attribution}</p>
      </Card>
      {data.explanation && <ExplanationCard explanation={data.explanation} onCite={onCite} />}
      {data.predictions.length > 0 && <PredictionTimeline predictions={data.predictions} onCite={onCite} />}
    </div>
  );
}
