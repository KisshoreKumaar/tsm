import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";

const TOKEN = "analyst-token-" + "x".repeat(32);

const principal = {
  name: "analyst-user",
  role: "analyst",
  permissions: ["read", "investigate"],
  two_person: false,
  version: "0.1.0",
  features: [
    {
      id: "core",
      name: "Core platform",
      description: "Identity, audit chain, jobs and live updates",
      nav: [{ path: "/overview", label: "Overview", section: "Operations", permission: "read", order: 10 }],
    },
  ],
};

function fakeFetch(): typeof fetch {
  return vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    const auth = (init?.headers as Record<string, string> | undefined)?.Authorization;
    if (auth !== `Bearer ${TOKEN}`) {
      return new Response(JSON.stringify({ error: { code: "unauthorized", message: "bad token" } }), { status: 401 });
    }
    return new Response(JSON.stringify(principal), { status: 200, headers: { "Content-Type": "application/json" } });
  }) as unknown as typeof fetch;
}

describe("App shell", () => {
  it("logs in with a token held in memory and locks again", async () => {
    const user = userEvent.setup();
    render(<App fetchImpl={fakeFetch()} />);

    await user.type(screen.getByLabelText("Operator token"), TOKEN);
    await user.click(screen.getByRole("button", { name: "Connect" }));

    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Overview" })).toBeInTheDocument();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect(document.cookie).toBe("");

    await user.click(screen.getByRole("button", { name: "Lock" }));
    expect(screen.getByLabelText("Operator token")).toHaveValue("");
  });

  it("rejects an invalid token", async () => {
    const user = userEvent.setup();
    render(<App fetchImpl={fakeFetch()} />);
    await user.type(screen.getByLabelText("Operator token"), "wrong-token-" + "y".repeat(32));
    await user.click(screen.getByRole("button", { name: "Connect" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("That token was not accepted.");
  });
});
