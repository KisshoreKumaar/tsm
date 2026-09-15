import { describe, expect, it } from "vitest";
import { parseSseBuffer } from "./sse";

describe("parseSseBuffer", () => {
  it("parses complete messages and keeps the partial remainder", () => {
    const buffer =
      ': connected\n\nid: 1\nevent: incident.updated\ndata: {"incident_id":"a"}\n\nid: 2\nevent: job.updated\ndata: {"jo';
    const { messages, rest } = parseSseBuffer(buffer);
    expect(messages).toEqual([{ id: "1", event: "incident.updated", data: { incident_id: "a" } }]);
    expect(rest).toBe('id: 2\nevent: job.updated\ndata: {"jo');
  });

  it("handles CRLF line endings, keep-alive comments and non-JSON data", () => {
    const { messages } = parseSseBuffer(": keep-alive\r\n\r\ndata: plain text\r\n\r\n");
    expect(messages).toEqual([{ id: null, event: "message", data: "plain text" }]);
  });

  it("joins multi-line data fields", () => {
    const { messages } = parseSseBuffer("event: note\ndata: line one\ndata: line two\n\n");
    expect(messages[0]?.data).toBe("line one\nline two");
  });
});
