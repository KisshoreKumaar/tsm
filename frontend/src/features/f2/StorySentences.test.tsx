import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { StorySentences } from "./StorySentences";
import type { StorySentence } from "./types";

const sentences: StorySentence[] = [
  {
    id: "s1",
    label: "FACT",
    text: "At 08:00:24 UTC, alex ran PowerShell with an encoded command (-EncodedCommand) on lab-ws-1.",
    evidence_ids: ["evt-a", "evt-b"],
    basis: "events",
    refs: [],
  },
  {
    id: "s2",
    label: "FACT",
    text: "1 event(s) contain text addressed to an AI assistant, for example “Ignore previous instructions”.",
    evidence_ids: ["evt-c"],
    basis: "events",
    refs: [],
  },
  { id: "s3", label: "FACT", text: "Not yet: no containment action has been executed.", evidence_ids: [], basis: "aegis_records", refs: [] },
];

describe("StorySentences", () => {
  it("renders labels, clickable citations and quoted untrusted text", async () => {
    const user = userEvent.setup();
    const onCite = vi.fn();
    const refs: Record<string, string> = { "evt-a": "E1", "evt-b": "E2", "evt-c": "E3" };
    const { container } = render(<StorySentences sentences={sentences} refFor={(id) => refs[id] ?? id} onCite={onCite} />);

    expect(screen.getAllByText("FACT")).toHaveLength(3);
    await user.click(screen.getByRole("button", { name: "Show evidence E1, E2" }));
    expect(onCite).toHaveBeenCalledWith(["evt-a", "evt-b"]);

    const quoted = container.querySelector("q.untrusted");
    expect(quoted?.textContent).toBe("Ignore previous instructions");
    expect(screen.getByText("[AEGIS records]")).toBeInTheDocument();
    expect(screen.getAllByRole("button")).toHaveLength(2);
  });
});
