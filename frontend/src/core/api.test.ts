import { describe, expect, it, vi } from "vitest";
import { ApiError, buildUrl, createApiClient } from "./api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("api client", () => {
  it("sends the bearer token in the Authorization header only", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ ok: true }));
    const api = createApiClient({ getToken: () => "secret-token", fetchImpl });
    await api.get("/me", { q: "x", empty: "", missing: undefined });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/me?q=x");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer secret-token");
    expect(url).not.toContain("secret-token");
    expect(init.credentials).toBe("omit");
  });

  it("maps structured error bodies and signals 401", async () => {
    const onUnauthorized = vi.fn();
    const fetchImpl = vi.fn(async () => jsonResponse({ error: { code: "unauthorized", message: "nope" } }, 401));
    const api = createApiClient({ getToken: () => "t", fetchImpl, onUnauthorized });
    await expect(api.get("/me")).rejects.toMatchObject({ status: 401, code: "unauthorized", message: "nope" });
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("serialises JSON bodies", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ id: "1" }, 201));
    const api = createApiClient({ getToken: () => null, fetchImpl });
    await api.post("/events", { kind: "auth_failure" });
    const [, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.body).toBe('{"kind":"auth_failure"}');
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("builds URLs", () => {
    expect(buildUrl("/api", "/incidents", { status: "OPEN", offset: 0 })).toBe("/api/incidents?status=OPEN&offset=0");
    expect(new ApiError(400, "bad", "m")).toBeInstanceOf(Error);
  });
});
