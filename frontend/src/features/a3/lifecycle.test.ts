import { describe, expect, it } from "vitest";
import { blockedReason, runsNow, versionNote } from "./lifecycle";
import type { RuleSummary } from "./types";

const base: RuleSummary = {
  id: "CUS-001",
  name: "Password spraying",
  status: "DRAFT",
  current_version: 1,
  approved_version: null,
  active_version: null,
  author: "engineer-user",
  source: "manual",
  source_incident_id: null,
  approved_by: null,
  approved_at: null,
  activated_by: null,
  activated_at: null,
  created_at: "2026-01-15T09:00:00+00:00",
  updated_at: "2026-01-15T09:00:00+00:00",
  builtin: false,
  allowed_actions: ["edit", "backtest", "retire"],
};

describe("rule lifecycle", () => {
  it("explains why approval and activation are blocked for a draft", () => {
    expect(blockedReason(base, "approve")).toBe("Backtest version 1 first");
    expect(blockedReason(base, "activate")).toBe("Approve version 1 first");
    expect(blockedReason(base, "disable")).toBe("This rule has never been activated");
    expect(blockedReason(base, "backtest")).toBeNull();
    expect(runsNow(base)).toBe(false);
    expect(versionNote(base)).toMatch(/does not detect anything/);
  });

  it("allows approval once tested and activation once approved", () => {
    const tested = { ...base, status: "TESTED" as const, allowed_actions: ["edit", "backtest", "approve", "retire"] as const };
    expect(blockedReason({ ...tested, allowed_actions: [...tested.allowed_actions] }, "approve")).toBeNull();
    const approved = {
      ...base,
      status: "APPROVED" as const,
      approved_version: 1,
      allowed_actions: ["edit", "backtest", "activate", "retire"] as RuleSummary["allowed_actions"],
    };
    expect(blockedReason(approved, "activate")).toBeNull();
  });

  it("says which version keeps running while a new one is drafted", () => {
    const edited: RuleSummary = {
      ...base,
      status: "DRAFT",
      current_version: 2,
      approved_version: 1,
      active_version: 1,
      allowed_actions: ["edit", "backtest", "disable", "retire"],
    };
    expect(runsNow(edited)).toBe(true);
    expect(versionNote(edited)).toBe("Version 2 is draft; version 1 keeps running until you activate the new one.");
    expect(blockedReason(edited, "activate")).toBe("Approve version 2 first");
    const disabled: RuleSummary = { ...edited, status: "DISABLED", allowed_actions: ["edit", "backtest", "retire"] };
    expect(runsNow(disabled)).toBe(false);
    expect(blockedReason(disabled, "disable")).toBe("This rule is already disabled");
  });
});
