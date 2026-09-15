import { useState } from "react";
import { Link } from "react-router-dom";
import { formatTime } from "../../core/format";
import type { Page } from "../../core/types";
import { EmptyState, ErrorBanner, Loading, Pagination, SeverityBadge } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import type { CampaignSummary } from "./types";

const LIMIT = 25;

export function CampaignsPage() {
  const [status, setStatus] = useState("ACTIVE");
  const [offset, setOffset] = useState(0);
  const { data, error, loading, refetch } = useApiQuery<Page<CampaignSummary>>("/campaigns", { status, offset, limit: LIMIT });
  useLiveEvents(["campaign"], refetch);

  return (
    <section>
      <h1>Campaigns</h1>
      <p className="muted">
        Groups of incidents linked by a shared user, external IP, domain or file hash across different assets within 24 hours. Every link is explained.
      </p>
      <div className="filters">
        <select aria-label="Campaign status" value={status} onChange={(e) => (setOffset(0), setStatus(e.target.value))}>
          <option value="ACTIVE">Active</option>
          <option value="MERGED">Merged</option>
          <option value="DISSOLVED">Dissolved</option>
        </select>
      </div>
      <ErrorBanner error={error} />
      {loading && !data && <Loading />}
      {data && data.items.length === 0 && <EmptyState>No campaigns. Try the lateral-movement demo scenario.</EmptyState>}
      {data && data.items.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Risk</th>
              <th>Campaign</th>
              <th>Incidents</th>
              <th>Assets</th>
              <th>Last activity</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((campaign) => (
              <tr key={campaign.id}>
                <td>
                  <SeverityBadge severity={campaign.severity} /> {campaign.risk_score}
                </td>
                <td>
                  <Link to={`/campaigns/${campaign.id}`}>{campaign.title}</Link>
                </td>
                <td>{campaign.incident_count}</td>
                <td className="small">{campaign.assets.join(", ")}</td>
                <td className="small">{formatTime(campaign.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && <Pagination offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />}
    </section>
  );
}
