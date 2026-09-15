import { useState } from "react";
import { Link } from "react-router-dom";
import type { Page } from "../../core/types";
import { formatTime } from "../../core/format";
import { EmptyState, ErrorBanner, Loading, Pagination, SeverityBadge, StatusBadge } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import type { IncidentSummary } from "./types";

const LIMIT = 25;

export function IncidentsPage() {
  const [q, setQ] = useState("");
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [sort, setSort] = useState("updated");
  const [offset, setOffset] = useState(0);
  const { data, error, loading, refetch } = useApiQuery<Page<IncidentSummary>>("/incidents", {
    q: search,
    status,
    severity,
    sort,
    offset,
    limit: LIMIT,
  });
  useLiveEvents(["incident"], refetch);

  return (
    <section>
      <h1>Incidents</h1>
      <form
        className="filters"
        onSubmit={(event) => {
          event.preventDefault();
          setOffset(0);
          setSearch(q.trim());
        }}
      >
        <input aria-label="Search incidents" placeholder="Search title, asset, user or ID" value={q} onChange={(e) => setQ(e.target.value)} />
        <select aria-label="Status" value={status} onChange={(e) => (setOffset(0), setStatus(e.target.value))}>
          <option value="">Active and closed</option>
          {["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "MERGED"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select aria-label="Severity" value={severity} onChange={(e) => (setOffset(0), setSeverity(e.target.value))}>
          <option value="">Any severity</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select aria-label="Sort" value={sort} onChange={(e) => setSort(e.target.value)}>
          <option value="updated">Recently updated</option>
          <option value="risk">Highest risk</option>
          <option value="first_seen">Newest activity</option>
        </select>
        <button type="submit">Search</button>
      </form>
      <ErrorBanner error={error} />
      {loading && !data && <Loading />}
      {data && data.items.length === 0 && <EmptyState>No incidents match these filters.</EmptyState>}
      {data && data.items.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Risk</th>
              <th>Status</th>
              <th>Incident</th>
              <th>Rules</th>
              <th>Events</th>
              <th>Owner</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((incident) => (
              <tr key={incident.id}>
                <td>
                  <SeverityBadge severity={incident.severity} /> {incident.risk_score}
                </td>
                <td>
                  <StatusBadge status={incident.status} />
                </td>
                <td>
                  <Link to={`/incidents/${incident.id}`}>{incident.title}</Link>
                </td>
                <td className="mono">{incident.rules.join(", ") || "—"}</td>
                <td>{incident.event_count}</td>
                <td>{incident.owner ?? "—"}</td>
                <td>{formatTime(incident.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && <Pagination offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />}
    </section>
  );
}
