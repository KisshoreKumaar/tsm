import type { ElementDefinition } from "cytoscape";

export type GraphNodeType = "incident" | "asset" | "user" | "source_ip" | "destination_ip" | "domain" | "file_hash";

export interface GraphNodeData {
  id: string;
  type: GraphNodeType;
  label: string;
  severity?: string;
  risk?: number;
  incident_id?: string;
  status?: string;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  kind: "membership" | "correlation";
  label: string;
  strength?: number;
  link_type?: string;
}

export interface GraphData {
  nodes: GraphNodeData[];
  edges: GraphEdgeData[];
  truncated: boolean;
}

/** Convert API graph data to Cytoscape elements, dropping edges whose endpoints were truncated away. */
export function toElements(graph: GraphData): ElementDefinition[] {
  const ids = new Set(graph.nodes.map((node) => node.id));
  const nodes: ElementDefinition[] = graph.nodes.map((node) => ({
    group: "nodes",
    data: { ...node },
    classes: [node.type, node.severity ? `sev-${node.severity.toLowerCase()}` : ""].filter(Boolean).join(" "),
  }));
  const edges: ElementDefinition[] = graph.edges
    .filter((edge) => ids.has(edge.source) && ids.has(edge.target))
    .map((edge) => ({ group: "edges", data: { ...edge }, classes: edge.kind }));
  return [...nodes, ...edges];
}
