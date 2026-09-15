import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { horizonText, PredictionCard } from "./PredictionCard";
import type { Prediction } from "./types";

const base: Prediction = {
  id: "p1",
  incident_id: "i1",
  technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", url: "https://attack.mitre.org/techniques/T1059/001/" },
  label: "HYPOTHESIS",
  score: 72,
  band: "HIGH",
  score_label: "Relative likelihood score (0-100). It is a heuristic, not a probability.",
  factors: [{ name: "transition_weight", label: "Curated transition weight", points: 45, max_points: 60, explanation: "T1078 → T1059.001" }],
  rationale: "With a working session, attackers commonly run PowerShell.",
  sources: [],
  evidence_ids: ["e1", "e2"],
  watch_signals: [{ description: "PowerShell process starts", kinds: ["process_start"], conditions: [], rule_ids: [], text: "process_start where process_name contains 'powershell'" }],
  preventive_actions: [{ text: "Consider requesting simulated isolation", playbook: "isolate_endpoint" }],
  horizon_seconds: 3600,
  predicted_at: "2026-01-15T09:00:00+00:00",
  expires_at: "2026-01-15T10:00:00+00:00",
  status: "WATCHING",
  observed_event_ids: [],
  observed_at: null,
  status_changed_at: "2026-01-15T09:00:00+00:00",
};

describe("PredictionCard", () => {
  it("labels predictions as heuristic hypotheses with watch signals", () => {
    render(<PredictionCard prediction={base} rank={1} onCite={() => {}} />);
    expect(screen.getByText("HYPOTHESIS")).toBeInTheDocument();
    expect(screen.getByText("Likelihood 72/100 · HIGH")).toHaveAttribute("title", expect.stringContaining("not a probability"));
    expect(screen.getByText("process_start where process_name contains 'powershell'")).toBeInTheDocument();
    expect(screen.getByText(/Watching until/)).toBeInTheDocument();
    expect(screen.getByText(/requires approval/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/\d+% (chance|probability)/i);
  });

  it("cites observed evidence once a prediction comes true", async () => {
    const user = userEvent.setup();
    const onCite = vi.fn();
    render(
      <PredictionCard
        prediction={{ ...base, status: "OBSERVED", observed_event_ids: ["e9"], observed_at: "2026-01-15T09:05:00+00:00" }}
        rank={2}
        onCite={onCite}
      />,
    );
    await user.click(screen.getByRole("button", { name: "show observed evidence (1)" }));
    expect(onCite).toHaveBeenCalledWith(["e9"]);
    await user.click(screen.getByRole("button", { name: "basis evidence (2)" }));
    expect(onCite).toHaveBeenLastCalledWith(["e1", "e2"]);
  });

  it("formats heuristic horizons", () => {
    expect(horizonText(3600)).toBe("1 h");
    expect(horizonText(5400)).toBe("1.5 h");
    expect(horizonText(900)).toBe("15 min");
  });
});
