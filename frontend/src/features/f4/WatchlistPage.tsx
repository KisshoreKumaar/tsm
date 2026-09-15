import { useState } from "react";
import { Link } from "react-router-dom";
import { formatTime } from "../../core/format";
import { EmptyState, ErrorBanner, Loading, StatusBadge } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import type { HitRate, WatchlistResponse } from "./types";
import "./prediction.css";

const percent = (value: number | null) => (value === null ? "—" : `${Math.round(value * 100)}%`);

export function WatchlistPage() {
  const [status, setStatus] = useState("WATCHING");
  const { data, error, loading, refetch } = useApiQuery<WatchlistResponse>("/predictions", { status: status || undefined });
  const { data: rate, refetch: refetchRate } = useApiQuery<HitRate>("/metrics/prediction-hit-rate");
  useLiveEvents(["prediction"], () => {
    refetch();
    refetchRate();
  });

  return (
    <section>
      <h1>Prediction watchlist</h1>
      <p className="muted">
        Likely next attacker steps across open incidents, drawn from a curated transition model. Every prediction is a hypothesis; AEGIS marks it
        observed when a matching event arrives within its heuristic horizon.
      </p>
      {rate && (
        <>
          <div className="tiles">
            <div className="tile">
              <div className="tile-value">{rate.watching}</div>
              <div className="tile-label">Watching</div>
            </div>
            <div className="tile">
              <div className="tile-value">{rate.observed}</div>
              <div className="tile-label">Observed</div>
            </div>
            <div className="tile">
              <div className="tile-value">{rate.expired}</div>
              <div className="tile-label">Expired</div>
            </div>
            <div className="tile">
              <div className="tile-value">{percent(rate.hit_rate)}</div>
              <div className="tile-label">Hit rate (observed / all)</div>
            </div>
            <div className="tile">
              <div className="tile-value">{percent(rate.resolved_hit_rate)}</div>
              <div className="tile-label">Hit rate (observed / resolved)</div>
            </div>
          </div>
          <p className="hint">{rate.label}</p>
        </>
      )}
      <div className="filters">
        <select aria-label="Prediction status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="WATCHING">Watching</option>
          <option value="OBSERVED">Observed</option>
          <option value="EXPIRED">Expired</option>
          <option value="">All</option>
        </select>
      </div>
      <ErrorBanner error={error} />
      {loading && !data && <Loading />}
      {data && data.items.length === 0 && <EmptyState>No predictions with this status.</EmptyState>}
      {data && data.items.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Likelihood</th>
              <th>Technique</th>
              <th>Tactic</th>
              <th>Status</th>
              <th>Incident</th>
              <th>Observed / expires</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((p) => (
              <tr key={p.id}>
                <td className="nowrap" title={data.label}>
                  {p.score} · {p.band}
                </td>
                <td>
                  <a className="technique" href={p.technique.url} target="_blank" rel="noreferrer noopener">
                    {p.technique.id}
                  </a>{" "}
                  {p.technique.name}
                </td>
                <td>{p.technique.tactic}</td>
                <td>
                  <StatusBadge status={p.status} />
                </td>
                <td>
                  <Link to={`/incidents/${p.incident_id}`}>{p.incident_title ?? p.incident_id.slice(0, 8)}</Link>
                </td>
                <td className="nowrap">{p.observed_at ? formatTime(p.observed_at) : formatTime(p.expires_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
