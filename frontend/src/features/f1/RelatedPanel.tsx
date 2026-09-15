import { useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Card, EmptyState, ErrorBanner, Loading, SeverityBadge, StatusBadge } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import type { IncidentTabProps } from "../core/incidentTabTypes";
import type { GraphData, GraphNodeData } from "./graphElements";
import { GraphLegend, GraphView } from "./GraphView";
import type { RelatedResponse } from "./types";

export function RelatedPanel({ incident, onCite }: IncidentTabProps) {
  const navigate = useNavigate();
  const { data, error, loading } = useApiQuery<RelatedResponse>(`/incidents/${incident.id}/related`, { revision: incident.revision });
  const { data: graph } = useApiQuery<GraphData>("/graph", { incident_id: incident.id, revision: incident.revision });
  const ownEvents = new Set(incident.events.map((event) => event.id));
  const onSelect = useCallback(
    (node: GraphNodeData) => {
      if (node.incident_id && node.incident_id !== incident.id) navigate(`/incidents/${node.incident_id}`);
    },
    [navigate, incident.id],
  );

  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBanner error={error} />;
  if (!data.campaign && data.links.length === 0) {
    return <EmptyState>No related incidents: nothing links this incident to others within the campaign window.</EmptyState>;
  }

  return (
    <div className="grid-2">
      <div>
        {data.campaign && (
          <Card title="Campaign">
            <p>
              <SeverityBadge severity={data.campaign.severity} /> <Link to={`/campaigns/${data.campaign.id}`}>{data.campaign.title}</Link>
            </p>
            <p className="muted small">
              {data.campaign.incident_count} incidents across {data.campaign.assets.length} assets
            </p>
          </Card>
        )}
        <Card title="Why they are linked">
          <ul className="plain">
            {data.links.map((link) => (
              <li key={link.id}>
                <span className="mono small">{link.link_type}</span> with{" "}
                <Link to={`/incidents/${link.other_incident_id}`}>{link.other_asset ?? link.other_incident_id}</Link>
                <div>{link.reason}</div>
                <button type="button" className="link" onClick={() => onCite(link.supporting_event_ids.filter((id) => ownEvents.has(id)))}>
                  show this incident&apos;s evidence
                </button>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Related incidents">
          <table className="table compact">
            <tbody>
              {data.related_incidents.map((related) => (
                <tr key={related.id}>
                  <td>
                    <SeverityBadge severity={related.severity} />
                  </td>
                  <td>
                    <Link to={`/incidents/${related.id}`}>{related.title}</Link>
                  </td>
                  <td>
                    <StatusBadge status={related.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
      {graph && (
        <Card title="Graph">
          <GraphLegend />
          <GraphView graph={graph} onSelect={onSelect} height={420} />
        </Card>
      )}
    </div>
  );
}
