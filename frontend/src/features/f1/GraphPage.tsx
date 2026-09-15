import { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, EmptyState, ErrorBanner, Loading } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import type { GraphData, GraphNodeData } from "./graphElements";
import { GraphLegend, GraphView } from "./GraphView";

export function GraphPage() {
  const navigate = useNavigate();
  const { data, error, loading, refetch } = useApiQuery<GraphData>("/graph", { limit: 150 });
  const [selected, setSelected] = useState<GraphNodeData | null>(null);
  useLiveEvents(["campaign", "incident"], refetch);

  const onSelect = useCallback(
    (node: GraphNodeData) => {
      setSelected(node);
      if (node.incident_id) {
        navigate(`/incidents/${node.incident_id}`);
      }
    },
    [navigate],
  );

  return (
    <section>
      <h1>Correlation graph</h1>
      <p className="muted">
        Incidents in active campaigns plus recent incidents. Dashed edges are explained links (shared user, external IP, domain or file hash within
        24 hours). Click an incident to open it.
      </p>
      <ErrorBanner error={error} />
      {loading && !data && <Loading />}
      {data && data.nodes.length === 0 && <EmptyState>No incidents to graph yet.</EmptyState>}
      {data && data.nodes.length > 0 && (
        <Card>
          <GraphLegend />
          <GraphView graph={data} onSelect={onSelect} height={620} />
          {data.truncated && <p className="hint">The graph was truncated to the first 150 incidents.</p>}
          {selected && !selected.incident_id && (
            <p className="small">
              Selected {selected.type.replace("_", " ")}: <span className="mono">{selected.label}</span>
            </p>
          )}
        </Card>
      )}
    </section>
  );
}
