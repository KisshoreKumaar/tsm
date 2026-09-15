import { describe, expect, it } from "vitest";
import { toElements, type GraphData } from "./graphElements";

describe("toElements", () => {
  it("maps nodes with type and severity classes and drops dangling edges", () => {
    const graph: GraphData = {
      truncated: true,
      nodes: [
        { id: "incident:1", type: "incident", label: "srv-1 · HIGH 70", severity: "HIGH", incident_id: "1" },
        { id: "user:svc", type: "user", label: "svc" },
      ],
      edges: [
        { id: "a", source: "incident:1", target: "user:svc", kind: "membership", label: "user" },
        { id: "b", source: "incident:1", target: "incident:2", kind: "correlation", label: "Shared user svc" },
      ],
    };
    const elements = toElements(graph);
    expect(elements).toHaveLength(3);
    expect(elements[0]?.classes).toBe("incident sev-high");
    expect(elements[1]?.classes).toBe("user");
    expect(elements[2]?.data.id).toBe("a");
  });
});
