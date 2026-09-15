import cytoscape from "cytoscape";
import { useEffect, useRef } from "react";
import { toElements, type GraphData, type GraphNodeData } from "./graphElements";
import "./correlation.css";

const COLORS: Record<string, string> = {
  incident: "#e5534b",
  asset: "#2a7fd4",
  user: "#3fb6a8",
  source_ip: "#d6a33a",
  destination_ip: "#b083f0",
  domain: "#f0883e",
  file_hash: "#8a9bab",
};

const STYLE: cytoscape.CytoscapeOptions["style"] = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      color: "#dbe5ef",
      "font-size": 10,
      "text-valign": "bottom",
      "text-margin-y": 4,
      width: 22,
      height: 22,
      "background-color": "#8a9bab",
      "border-width": 1,
      "border-color": "#243242",
    },
  },
  ...Object.entries(COLORS).map(([type, color]) => ({ selector: `node.${type}`, style: { "background-color": color } })),
  { selector: "node.incident", style: { shape: "round-rectangle", width: 30, height: 30 } },
  { selector: "node.sev-critical", style: { "border-width": 3, "border-color": "#ff7b72" } },
  {
    selector: "edge",
    style: { width: 1, "line-color": "#35475a", "curve-style": "bezier", opacity: 0.8 },
  },
  {
    selector: "edge.correlation",
    style: {
      width: 2.5,
      "line-color": "#3fb6a8",
      "line-style": "dashed",
      label: "data(label)",
      "font-size": 8,
      color: "#8a9bab",
      "text-rotation": "autorotate",
      "text-wrap": "ellipsis",
      "text-max-width": "160px",
    },
  },
];

export function GraphLegend() {
  return (
    <div className="graph-legend">
      {Object.entries(COLORS).map(([type, color]) => (
        <span key={type} style={{ ["--dot" as string]: color }}>
          {type.replace("_", " ")}
        </span>
      ))}
      <span style={{ ["--dot" as string]: "transparent" }}>dashed edge = explained correlation link</span>
    </div>
  );
}

export function GraphView({ graph, onSelect, height = 520 }: { graph: GraphData; onSelect?: (node: GraphNodeData) => void; height?: number }) {
  const container = useRef<HTMLDivElement | null>(null);
  const selectRef = useRef(onSelect);

  useEffect(() => {
    selectRef.current = onSelect;
  }, [onSelect]);

  useEffect(() => {
    if (!container.current) {
      return;
    }
    const cy = cytoscape({
      container: container.current,
      elements: toElements(graph),
      style: STYLE,
      layout: { name: "cose", animate: false, padding: 30, nodeRepulsion: () => 9000 },
      minZoom: 0.2,
      maxZoom: 3,
    });
    cy.on("tap", "node", (event: cytoscape.EventObject) => {
      selectRef.current?.(event.target.data() as GraphNodeData);
    });
    return () => cy.destroy();
  }, [graph]);

  return <div ref={container} className="graph" style={{ height }} role="img" aria-label="Correlation graph of incidents and shared entities" />;
}
