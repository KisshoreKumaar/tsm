import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ConfirmDialog } from "./ConfirmDialog";

describe("ConfirmDialog", () => {
  it("requires the exact confirmation phrase", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    render(<ConfirmDialog title="Approve?" phrase="APPROVE SIMULATION" confirmLabel="Approve" onConfirm={onConfirm} onCancel={() => {}} />);
    const button = screen.getByRole("button", { name: "Approve" });
    expect(button).toBeDisabled();
    await user.type(screen.getByLabelText("Confirmation phrase"), "approve simulation");
    expect(button).toBeDisabled();
    await user.clear(screen.getByLabelText("Confirmation phrase"));
    await user.type(screen.getByLabelText("Confirmation phrase"), "APPROVE SIMULATION");
    expect(button).toBeEnabled();
    await user.click(button);
    expect(onConfirm).toHaveBeenCalledWith({ phrase: "APPROVE SIMULATION", reason: "" });
  });

  it("requires a reason when asked", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    render(<ConfirmDialog title="Reject?" reasonLabel="Reason" confirmLabel="Reject" onConfirm={onConfirm} onCancel={() => {}} />);
    expect(screen.getByRole("button", { name: "Reject" })).toBeDisabled();
    await user.type(screen.getByLabelText("Reason"), "Not needed");
    await user.click(screen.getByRole("button", { name: "Reject" }));
    expect(onConfirm).toHaveBeenCalledWith({ phrase: "", reason: "Not needed" });
  });
});
