import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../core/auth";
import { errorMessage, formatTime } from "../../core/format";
import { Card, EmptyState, ErrorBanner, Loading } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import { SuggestionCard } from "./SuggestionCard";
import { SuppressionsTable } from "./SuppressionsTable";
import type { FalsePositiveAnalytics, Suggestion, SuggestionStatus, SuppressionsResponse } from "./types";
import "./tuning.css";

const STATUSES: SuggestionStatus[] = ["PROPOSED", "APPROVED", "REJECTED", "REVERTED"];

interface SuppressedDetection {
  id: string;
  rule_id: string;
  incident_id: string | null;
  summary: string;
  first_ts: string;
  suppression_id: string | null;
  suppression_status: string | null;
  suppression_expires_at: string | null;
  event_count: number;
}

const percent = (value: number | null) => (value === null ? "—" : `${Math.round(value * 100)}%`);

export function TuningPage() {
  const { api, can } = useAuth();
  const [status, setStatus] = useState<SuggestionStatus>("PROPOSED");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const analytics = useApiQuery<FalsePositiveAnalytics>("/tuning/fp-analytics", { days: 30 });
  const suggestions = useApiQuery<{ items: Suggestion[] }>("/tuning/suggestions", { status });
  const suppressions = useApiQuery<SuppressionsResponse>("/suppressions");
  const suppressed = useApiQuery<{ items: SuppressedDetection[] }>("/tuning/suppressed-detections", { limit: 25 });

  function refreshAll() {
    analytics.refetch();
    suggestions.refetch();
    suppressions.refetch();
    suppressed.refetch();
  }

  useLiveEvents(["tuning"], refreshAll);

  async function generate() {
    setBusy(true);
    setError(null);
    try {
      await api.post("/tuning/suggestions/generate", {});
      refreshAll();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const data = analytics.data;
  const maxTrend = Math.max(1, ...(data?.trend ?? []).map((point) => point.false_positives));

  return (
    <section>
      <h1>Tuning</h1>
      <p className="muted">
        AEGIS learns from false-positive verdicts and proposes narrow, reversible changes. Every suggestion is
        simulated against stored alerts first, an approver applies it, and it can be reverted or left to expire.
      </p>
      <ErrorBanner error={error ? new Error(error) : (analytics.error ?? suggestions.error)} />
      {analytics.loading && !data && <Loading />}
      {data && (
        <>
          <div className="tiles">
            <div className="tile">
              <div className="tile-value">{data.false_positive_closures}</div>
              <div className="tile-label">False-positive closures</div>
            </div>
            <div className="tile">
              <div className="tile-value">{percent(data.false_positive_rate)}</div>
              <div className="tile-label">Of closed incidents</div>
            </div>
            <div className="tile">
              <div className="tile-value">{suggestions.data?.items.length ?? 0}</div>
              <div className="tile-label">{status.toLowerCase()} suggestions</div>
            </div>
            <div className="tile">
              <div className="tile-value">{suppressions.data?.items.filter((item) => item.applies).length ?? 0}</div>
              <div className="tile-label">Active suppressions</div>
            </div>
          </div>
          <p className="hint">{data.label}</p>
          <div className="grid-2">
            <Card title="False positives by rule">
              <table className="table compact">
                <tbody>
                  {data.per_rule.map((row) => (
                    <tr key={row.rule_id}>
                      <td className="mono">{row.rule_id}</td>
                      <td className="nowrap">
                        {row.false_positives}/{row.incidents}
                      </td>
                      <td className="muted small">{percent(row.rate)}</td>
                    </tr>
                  ))}
                  {data.per_rule.length === 0 && (
                    <tr>
                      <td className="muted">No incidents yet.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </Card>
            <Card title="Entities in false positives">
              <table className="table compact">
                <tbody>
                  {data.per_entity.slice(0, 8).map((entity) => (
                    <tr key={`${entity.type}-${entity.value}`}>
                      <td className="small muted">{entity.type}</td>
                      <td className="mono small">{entity.value}</td>
                      <td className="nowrap small">
                        {entity.incidents} incident(s){entity.marked_benign > 0 ? `, ${entity.marked_benign} marked benign` : ""}
                      </td>
                    </tr>
                  ))}
                  {data.per_entity.length === 0 && (
                    <tr>
                      <td className="muted">Nothing closed as a false positive yet.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </Card>
            <Card title="Reasons given">
              <ul className="plain small">
                {data.per_category.map((row) => (
                  <li key={row.category}>
                    {row.category.replaceAll("_", " ")}: {row.count}
                  </li>
                ))}
                {data.per_category.length === 0 && <li className="muted">No verdicts recorded.</li>}
              </ul>
            </Card>
            <Card title={`Trend (${data.days} days)`}>
              {data.trend.length === 0 ? (
                <p className="muted small">No false-positive closures in this period.</p>
              ) : (
                <ul className="plain small">
                  {data.trend.map((point) => (
                    <li key={point.day}>
                      <span className="mono">{point.day}</span>{" "}
                      <span
                        className="likelihood-bar"
                        style={{ display: "inline-block", width: `${(point.false_positives / maxTrend) * 60}%` }}
                        aria-hidden="true"
                      >
                        <span style={{ width: "100%" }} />
                      </span>{" "}
                      {point.false_positives}
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        </>
      )}

      <Card
        title="Suggestions"
        actions={
          can("tuning.draft") && (
            <button type="button" className="ghost" onClick={generate} disabled={busy}>
              {busy ? "Looking…" : "Look for tuning now"}
            </button>
          )
        }
      >
        <div className="filters">
          <select
            aria-label="Suggestion status"
            value={status}
            onChange={(event) => setStatus(event.target.value as SuggestionStatus)}
          >
            {STATUSES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        {suggestions.loading && !suggestions.data && <Loading />}
        {suggestions.data?.items.length === 0 && (
          <EmptyState>
            No {status.toLowerCase()} suggestions. AEGIS proposes one after three incidents of the same rule are closed
            as false positives with a shared entity.
          </EmptyState>
        )}
        <div className="suggestion-list">
          {suggestions.data?.items.map((suggestion) => (
            <SuggestionCard key={suggestion.id} suggestion={suggestion} onChanged={refreshAll} />
          ))}
        </div>
      </Card>

      <Card title="Active tuning">
        {suppressions.data ? <SuppressionsTable data={suppressions.data} onChanged={refreshAll} /> : <Loading />}
      </Card>

      <Card title="Suppressed detections">
        <p className="hint">Suppressed detections are kept, never deleted, so you can always see what was hidden.</p>
        {suppressed.data && suppressed.data.items.length === 0 && <EmptyState>Nothing is suppressed.</EmptyState>}
        {suppressed.data && suppressed.data.items.length > 0 && (
          <table className="table compact">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Detection</th>
                <th>Incident</th>
                <th>Suppression</th>
              </tr>
            </thead>
            <tbody>
              {suppressed.data.items.map((detection) => (
                <tr key={detection.id}>
                  <td className="mono">{detection.rule_id}</td>
                  <td className="small">
                    {detection.summary}
                    <div className="muted">
                      {formatTime(detection.first_ts)} · {detection.event_count} event(s)
                    </div>
                  </td>
                  <td className="small">
                    {detection.incident_id ? (
                      <Link to={`/incidents/${detection.incident_id}`} className="mono">
                        {detection.incident_id.slice(0, 8)}
                      </Link>
                    ) : (
                      <span className="muted">no incident</span>
                    )}
                  </td>
                  <td className="small muted">
                    {detection.suppression_status ?? "—"}
                    {detection.suppression_expires_at ? ` until ${formatTime(detection.suppression_expires_at)}` : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </section>
  );
}
