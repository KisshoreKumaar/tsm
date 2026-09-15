import { useCallback, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useAuth } from "../../core/auth";
import { formatTime, shortId } from "../../core/format";
import { Card, ErrorBanner, KeyValues, Loading, SeverityBadge, StatusBadge, Tabs } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import { StoryView } from "../f2/StoryView";
import type { StoryResponse } from "../f2/types";
import type { GraphData, GraphNodeData } from "./graphElements";
import { GraphLegend, GraphView } from "./GraphView";
import type { CampaignDetail } from "./types";

type TabId = "links" | "story" | "graph" | "timeline";

function CampaignStory({ campaignId, onCite }: { campaignId: string; onCite: (ids: string[]) => void }) {
  const { data, error, loading } = useApiQuery<StoryResponse>(`/campaigns/${campaignId}/story`);
  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBanner error={error} />;
  return <StoryView data={data} onCite={onCite} exportPath={`/campaigns/${campaignId}/story.md`} />;
}

export function CampaignPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { principal } = useAuth();
  const [tab, setTab] = useState<TabId>("links");
  const [highlight, setHighlight] = useState<Set<string>>(new Set());
  const { data, error, loading, refetch } = useApiQuery<CampaignDetail>(`/campaigns/${id}`);
  const { data: graph, refetch: refetchGraph } = useApiQuery<GraphData>("/graph", { campaign_id: id });
  useLiveEvents(["campaign"], () => {
    refetch();
    refetchGraph();
  });
  const storyEnabled = principal?.features.some((feature) => feature.id === "f2") ?? false;
  const assetsByIncident = useMemo(() => new Map((data?.incidents ?? []).map((incident) => [incident.id, incident.asset])), [data]);
  const onSelect = useCallback((node: GraphNodeData) => node.incident_id && navigate(`/incidents/${node.incident_id}`), [navigate]);

  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBanner error={error ?? new Error("Campaign not found")} />;

  const cite = (ids: string[]) => {
    setHighlight(new Set(ids));
    setTab("timeline");
  };

  return (
    <section>
      <p className="muted small">
        <Link to="/campaigns">Campaigns</Link> / {data.id}
      </p>
      <h1>{data.title}</h1>
      <div className="header-badges">
        <SeverityBadge severity={data.severity} />
        <span className="badge">Risk {data.risk_score}/100 (heuristic)</span>
        <StatusBadge status={data.status} />
        {data.merged_into && (
          <Link to={`/campaigns/${data.merged_into}`} className="badge">
            merged into {shortId(data.merged_into)}
          </Link>
        )}
      </div>
      <KeyValues
        items={[
          ["Incidents", data.incident_count],
          ["Assets", data.assets.join(", ")],
          ["Users", data.users.join(", ")],
          ["First activity", formatTime(data.first_seen)],
          ["Last activity", formatTime(data.last_seen)],
        ]}
      />
      <Card title="Member incidents">
        <table className="table compact">
          <tbody>
            {data.incidents.map((incident) => (
              <tr key={incident.id}>
                <td>
                  <SeverityBadge severity={incident.severity} /> {incident.risk_score}
                </td>
                <td>
                  <Link to={`/incidents/${incident.id}`}>{incident.title}</Link>
                </td>
                <td>
                  <StatusBadge status={incident.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <Tabs<TabId>
        tabs={[
          { id: "links", label: `Link reasons (${data.links.length})` },
          ...(storyEnabled ? [{ id: "story" as const, label: "Story" }] : []),
          { id: "graph", label: "Graph" },
          { id: "timeline", label: `Combined timeline (${data.timeline.length})` },
        ]}
        active={tab}
        onChange={setTab}
      />
      {tab === "links" && (
        <Card>
          <table className="table">
            <thead>
              <tr>
                <th>Assets</th>
                <th>Reason</th>
                <th>Strength</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {data.links.map((link) => (
                <tr key={link.id}>
                  <td className="small">
                    {link.asset_a} ↔ {link.asset_b}
                  </td>
                  <td>
                    <span className="mono small">{link.link_type}</span>
                    <div>{link.reason}</div>
                  </td>
                  <td className="nowrap">
                    <span className="strength-bar" style={{ width: `${Math.round(link.strength * 60)}px` }} />
                    {link.strength.toFixed(2)}
                  </td>
                  <td>
                    <button type="button" className="link" onClick={() => cite(link.supporting_event_ids)}>
                      {link.supporting_event_ids.length} event(s)
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="hint">Link strength is a heuristic weight by entity type, reduced for activity further apart in time.</p>
        </Card>
      )}
      {tab === "story" && storyEnabled && <CampaignStory campaignId={data.id} onCite={cite} />}
      {tab === "graph" && graph && (
        <Card>
          <GraphLegend />
          <GraphView graph={graph} onSelect={onSelect} />
        </Card>
      )}
      {tab === "timeline" && (
        <Card
          actions={
            highlight.size > 0 && (
              <button type="button" className="ghost" onClick={() => setHighlight(new Set())}>
                Clear highlight ({highlight.size})
              </button>
            )
          }
        >
          <table className="table timeline">
            <thead>
              <tr>
                <th>Time</th>
                <th>Asset</th>
                <th>Kind</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {data.timeline.map((event) => (
                <tr key={event.id} className={highlight.has(event.id) ? "highlight" : undefined}>
                  <td className="small nowrap">{formatTime(event.timestamp)}</td>
                  <td className="small">
                    <Link to={`/incidents/${event.incident_id}`}>{assetsByIncident.get(event.incident_id) ?? event.asset}</Link>
                  </td>
                  <td className="mono small">{event.kind}</td>
                  <td className="small">{event.details && <blockquote className="quoted">{event.details}</blockquote>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.timeline_truncated && <p className="hint">Showing the first 500 events.</p>}
        </Card>
      )}
    </section>
  );
}
