import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiKeyField } from "./ApiKeyField";

const KEY = "gsk_live_0123456789abcdef";

describe("ApiKeyField", () => {
  it("submits the key once and clears it immediately", async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn(async () => {});
    const { container } = render(<ApiKeyField onSubmit={onSubmit} />);
    const input = screen.getByLabelText("API key");
    expect(input).toHaveAttribute("type", "password");
    await user.type(input, KEY);
    await user.click(screen.getByRole("button", { name: "Save key" }));
    expect(onSubmit).toHaveBeenCalledWith(KEY);
    expect(input).toHaveValue("");
    await waitFor(() => expect(screen.getByText(/will not be shown again/)).toBeInTheDocument());
    expect(container.innerHTML).not.toContain(KEY);
    expect(window.localStorage.length).toBe(0);
  });

  it("clears the key even when saving fails", async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn(async () => {
      throw new Error("Set AEGIS_SECRET_KEY on the server before storing API keys");
    });
    render(<ApiKeyField onSubmit={onSubmit} />);
    await user.type(screen.getByLabelText("API key"), KEY);
    await user.click(screen.getByRole("button", { name: "Save key" }));
    expect(screen.getByLabelText("API key")).toHaveValue("");
    expect(await screen.findByRole("alert")).toHaveTextContent("AEGIS_SECRET_KEY");
  });

  it("is disabled with a reason when the server cannot store keys", () => {
    render(<ApiKeyField onSubmit={async () => {}} disabled disabledReason="Server secret not configured" />);
    expect(screen.getByLabelText("API key")).toBeDisabled();
    expect(screen.getByPlaceholderText("Server secret not configured")).toBeInTheDocument();
  });
});
