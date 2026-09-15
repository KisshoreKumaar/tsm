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
      description: "Ingestion, detection, incidents, simulated response and audit",
      nav: [
        { path: "/overview", label: "Overview", section: "Operations", permission: "read", order: 10 },
        { path: "/incidents", label: "Incidents", section: "Operations", permission: "read", order: 20 },
      ],
    },
  ],
};

const overview = {
  metrics: { events_24h: 19, events_total: 19, highest_open_risk: 77 },
  incidents_by_status: { OPEN: 1 },
  open_incidents_by_severity: { HIGH: 1 },
  responses_by_status: {},
  top_incidents: [],
  generated_at: "2026-01-15T09:00:00+00:00",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function fakeFetch(): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const auth = (init?.headers as Record<string, string> | undefined)?.Authorization;
    if (auth !== `Bearer ${TOKEN}`) {
      return json({ error: { code: "unauthorized", message: "bad token" } }, 401);
    }
    if (url.startsWith("/api/me")) {
      return json(principal);
    }
    if (url.startsWith("/api/overview")) {
      return json(overview);
    }
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
}

describe("App shell", () => {
  it("logs in with a token held in memory, renders manifest navigation and locks again", async () => {
    const user = userEvent.setup();
    render(<App fetchImpl={fakeFetch()} />);

    await user.type(screen.getByLabelText("Operator token"), TOKEN);
    await user.click(screen.getByRole("button", { name: "Connect" }));

    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Incidents" })).toBeInTheDocument();
    expect(await screen.findByText("Highest open risk")).toBeInTheDocument();
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
