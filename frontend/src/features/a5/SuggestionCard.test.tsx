import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { describeScope, SuggestionCardView } from "./SuggestionCard";
import type { Impact, Suggestion } from "./types";

const impact: Impact = {
  range: { start: "2026-01-01T00:00:00+00:00", end: "2026-01-15T09:00:00+00:00" },
  events_scanned: 120,
  truncated: false,
  alerts_before: 4,
  alerts_removed: 3,
  false_positive_alerts_removed: 3,
  true_positive_alerts_removed: 0,
  unlinked_alerts_removed: 0,
  false_positive_incidents_affected: 3,
  true_positive_incidents_affected: [],
  true_positive_incidents_lost: [],
  true_positives_lost: 0,
  red_flag: false,
  sample_removed: [],
  label: "Simulated over stored events in the range.",
};

const base: Suggestion = {
  id: "s1",
  type: "suppression",
  rule_id: "NET-001",
  status: "PROPOSED",
  scope: { entities: [{ type: "source_ip", value: "10.20.0.250" }], expires_in_days: 30 },
  rationale: "Three scanner incidents were closed as false positives.",
  evidence: { closures: 3 },
  impact,
  impact_at: "2026-01-15T09:00:00+00:00",
  source: "deterministic",
  ai_rank: null,
  ai_rationale: null,
  applied: null,
  created_by: "system:tuning",
  created_at: "2026-01-15T09:00:00+00:00",
  updated_at: "2026-01-15T09:00:00+00:00",
  decided_by: null,
  decided_at: null,
  decision_note: null,
  protected_rule: false,
  requires: { protected_rule_acknowledgement: false, true_positive_loss_acknowledgement: false },
};

function renderCard(suggestion: Suggestion, canApprove = true) {
  const onApprove = vi.fn(async () => {});
  const onReject = vi.fn(async () => {});
  render(
    <MemoryRouter>
      <SuggestionCardView
        suggestion={suggestion}
        canApprove={canApprove}
        canDraft
        onApprove={onApprove}
        onReject={onReject}
        onSimulate={async () => {}}
        onRevert={async () => {}}
      />
    </MemoryRouter>,
  );
  return { onApprove, onReject };
}

describe("SuggestionCardView", () => {
  it("shows the simulated impact and approves a safe change with its expiry", async () => {
    const user = userEvent.setup();
    const { onApprove } = renderCard(base);
    expect(screen.getByText("source_ip 10.20.0.250")).toBeInTheDocument();
    expect(screen.queryByText(/not closed as false positives/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review and approve" }));
    const expiry = screen.getByLabelText("Expires in days");
    await user.clear(expiry);
    await user.type(expiry, "14");
    await user.click(screen.getByRole("button", { name: "Approve and apply" }));
    expect(onApprove).toHaveBeenCalledWith({
      expires_in_days: 14,
      acknowledge_protected_rule: false,
      acknowledge_true_positive_loss: false,
    });
  });

  it("requires both acknowledgements for a protected rule that would remove true positives", async () => {
    const user = userEvent.setup();
    const risky: Suggestion = {
      ...base,
      rule_id: "FILE-001",
      protected_rule: true,
      impact: { ...impact, true_positive_alerts_removed: 1, true_positives_lost: 0, red_flag: true },
      requires: { protected_rule_acknowledgement: true, true_positive_loss_acknowledgement: true },
    };
    const { onApprove } = renderCard(risky);
    expect(screen.getByText(/would also remove 1 alert/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review and approve" }));
    const apply = screen.getByRole("button", { name: "Approve and apply" });
    expect(apply).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /protected rule/ }));
    expect(apply).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /not closed as false positives/ }));
    expect(apply).toBeEnabled();
    await user.click(apply);
    expect(onApprove).toHaveBeenCalledWith({
      expires_in_days: 30,
      acknowledge_protected_rule: true,
      acknowledge_true_positive_loss: true,
    });
  });

  it("hides approval from roles without the permission and requires a rejection reason", async () => {
    const user = userEvent.setup();
    const { onReject } = renderCard(base, false);
    expect(screen.queryByRole("button", { name: "Review and approve" })).not.toBeInTheDocument();
    expect(screen.getByText(/cannot approve|not approve/i)).toBeInTheDocument();
    expect(describeScope({ ...base, scope: { threshold: 20 } })).toBe("threshold 20");
    expect(onReject).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Re-simulate" }));
  });
});
