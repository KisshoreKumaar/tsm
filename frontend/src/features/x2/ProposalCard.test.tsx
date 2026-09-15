import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { INJECTION_PHRASE, ProposalCardView } from "./ProposalCard";
import type { Proposal } from "./types";

const base: Proposal = {
  id: "p1",
  chat_id: "c1",
  job_id: "j1",
  action: "incident.update",
  target_type: "incident",
  target_id: "11111111-2222-3333-4444-555555555555",
  target_revision: 3,
  required_permission: "investigate",
  payload: { status: "INVESTIGATING", note: "Taking ownership" },
  rationale: "High-risk login",
  evidence_ids: ["e1"],
  injection_context: false,
  status: "PROPOSED",
  result: null,
  created_by: "ai:agent (for analyst-user)",
  created_at: "2026-01-15T09:00:00+00:00",
  decided_by: null,
  decided_at: null,
  decision_note: null,
};

function renderCard(proposal: Proposal, canApply = true) {
  const onApply = vi.fn(async () => {});
  const onDismiss = vi.fn(async () => {});
  render(
    <MemoryRouter>
      <ProposalCardView proposal={proposal} canApply={canApply} canDismiss onApply={onApply} onDismiss={onDismiss} />
    </MemoryRouter>,
  );
  return { onApply, onDismiss };
}

describe("ProposalCardView", () => {
  it("applies only after explicit confirmation", async () => {
    const user = userEvent.setup();
    const { onApply } = renderCard(base);
    expect(onApply).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Review and apply" }));
    expect(screen.getByRole("dialog")).toHaveTextContent("under your identity");
    await user.click(screen.getByRole("button", { name: "Apply as me" }));
    expect(onApply).toHaveBeenCalledWith(false);
  });

  it("requires typed acknowledgement when drafted in injection context", async () => {
    const user = userEvent.setup();
    const { onApply } = renderCard({ ...base, injection_context: true });
    expect(screen.getByText(/instruction-like text was present/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review and apply" }));
    const apply = screen.getByRole("button", { name: "Apply as me" });
    expect(apply).toBeDisabled();
    await user.type(screen.getByLabelText("Confirmation phrase"), INJECTION_PHRASE);
    await user.click(apply);
    expect(onApply).toHaveBeenCalledWith(true);
  });

  it("hides apply for roles without the target permission and requires a dismissal reason", async () => {
    const user = userEvent.setup();
    const { onDismiss } = renderCard(base, false);
    expect(screen.queryByRole("button", { name: "Review and apply" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Dismiss" }));
    const confirm = screen.getAllByRole("button", { name: "Dismiss" }).at(-1)!;
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText("Reason"), "Not needed");
    await user.click(confirm);
    expect(onDismiss).toHaveBeenCalledWith("Not needed");
  });
});
