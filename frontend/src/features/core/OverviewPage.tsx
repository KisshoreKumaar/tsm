import { Link } from "react-router-dom";
import { Card, ErrorBanner, Loading, SeverityBadge, StatusBadge } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import type { IncidentSummary } from "./types";

interface Overview {
  metrics: Record<string, number>;
  incidents_by_status: Record<string, number>;
  open_incidents_by_severity: Record<string, number>;
  responses_by_status: Record<string, number>;
  top_incidents: IncidentSummary[];
  generated_at: string;
}

const TILES: [string, string][] = [
  ["events_24h", "Events (24 h)"],
  ["events_total", "Events stored"],
  ["highest_open_risk", "Highest open risk"],
  ["detections_active", "Active detections"],
  ["injection_suspected_events", "Injection-flagged events"],
  ["isolated_endpoints", "Isolated endpoints (simulated)"],
  ["audit_records", "Audit records"],
  ["jobs_queued", "Jobs queued"],
];

export function OverviewPage() {
  const { data, error, loading, refetch } = useApiQuery<Overview>("/overview");
  useLiveEvents(["incident", "events", "response"], refetch);

  if (loading && !data) {
    return <Loading />;
  }
  return (
    <section>
      <h1>Overview</h1>
      <ErrorBanner error={error} />
      {data && (
        <>
          <div className="tiles">
            {TILES.map(([key, label]) => (
              <div key={key} className="tile">
                <div className="tile-value">{data.metrics[key] ?? 0}</div>
                <div className="tile-label">{label}</div>
              </div>
            ))}
          </div>
          <div className="grid-2">
            <Card title="Open incidents by severity">
              <ul className="plain">
                {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((severity) => (
                  <li key={severity}>
                    <SeverityBadge severity={severity} /> {data.open_incidents_by_severity[severity] ?? 0}
                  </li>
                ))}
              </ul>
            </Card>
            <Card title="Incidents by status">
              <ul className="plain">
                {Object.entries(data.incidents_by_status).map(([status, count]) => (
                  <li key={status}>
                    <StatusBadge status={status} /> {count}
                  </li>
                ))}
                {Object.keys(data.incidents_by_status).length === 0 && <li className="muted">No incidents yet</li>}
              </ul>
            </Card>
          </div>
          <Card title="Highest-risk open incidents">
            {data.top_incidents.length === 0 ? (
              <p className="muted">
                No open incidents. Load a <Link to="/demo">demo scenario</Link> to see AEGIS in action.
              </p>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>Risk</th>
                    <th>Incident</th>
                    <th>Rules</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_incidents.map((incident) => (
                    <tr key={incident.id}>
                      <td>
                        <SeverityBadge severity={incident.severity} /> {incident.risk_score}
                      </td>
                      <td>
                        <Link to={`/incidents/${incident.id}`}>{incident.title}</Link>
                      </td>
                      <td className="mono">{incident.rules.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
          <p className="hint">Risk scores are heuristics that rank attention; they are not probabilities.</p>
        </>
      )}
    </section>
  );
}
