import { describe, expect, it } from "vitest";
import { parseEventImport } from "./importEvents";

describe("parseEventImport", () => {
  it("accepts arrays, batch objects, single objects and JSON Lines", () => {
    expect(parseEventImport('[{"kind":"a"},{"kind":"b"}]')).toHaveLength(2);
    expect(parseEventImport('{"events":[{"kind":"a"}]}')).toHaveLength(1);
    expect(parseEventImport('{"kind":"a"}')).toEqual([{ kind: "a" }]);
    expect(parseEventImport('{"kind":"a"}\n\n{"kind":"b"}\n')).toHaveLength(2);
  });

  it("rejects invalid input with a clear message", () => {
    expect(() => parseEventImport("")).toThrow("at least one event");
    expect(() => parseEventImport('{"kind":"a"}\nnot json')).toThrow("Line 2");
    expect(() => parseEventImport("[1, 2]")).toThrow("Item 1 is not a JSON object");
  });
});
