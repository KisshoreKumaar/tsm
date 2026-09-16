import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DeadlineBadge, remainingText } from "./DeadlineBadge";
import type { DeadlineInfo } from "./types";

const base: DeadlineInfo = {
  deadline_utc: "2026-01-15T15:00:00+00:00",
  deadline_ist: "2026-01-15T20:30:00+05:30",
  window_hours: 6,
  seconds_remaining: 18_000,
  overdue: false,
  state: "ok",
  label: "Counted from the first detection time using the configured window.",
};

describe("DeadlineBadge", () => {
  it("counts down in UTC by default and can show IST", () => {
    const { rerender } = render(<DeadlineBadge deadline={base} />);
    expect(screen.getByText(/5 h 0 m left/)).toBeInTheDocument();
    expect(screen.getByText(/2026-01-15 15:00:00\+00:00 UTC/)).toBeInTheDocument();
    rerender(<DeadlineBadge deadline={base} timezone="IST" />);
    expect(screen.getByText(/2026-01-15 20:30:00\+05:30 IST/)).toBeInTheDocument();
  });

  it("marks an overdue deadline and carries the basis as a tooltip", () => {
    render(<DeadlineBadge deadline={{ ...base, seconds_remaining: -60, overdue: true, state: "overdue" }} />);
    const badge = screen.getByText(/Reporting deadline passed/);
    expect(badge).toHaveAttribute("title", expect.stringContaining("first detection time"));
    expect(badge.className).toContain("deadline-overdue");
  });

  it("formats remaining time by size", () => {
    expect(remainingText(0)).toBe("overdue");
    expect(remainingText(1_800)).toBe("30 m left");
    expect(remainingText(7_200)).toBe("2 h 0 m left");
    expect(remainingText(180_000)).toBe("2 d 2 h left");
  });
});
