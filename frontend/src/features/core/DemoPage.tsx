import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../core/auth";
import { errorMessage, shortId } from "../../core/format";
import { Card, ErrorBanner, Loading } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";

interface ScenarioInfo {
  id: string;
  name: string;
  description: string;
  steps: { label: string; events: number }[];
  event_count: number;
  expected: { incidents: number; campaigns: number; rules: string[] };
  late_arrival: boolean;
}

interface RunResult {
  run_id: string;
  scenario: string;
  mode: "instant" | "replay";
  suffix: string;
  steps: { label: string; events: number }[];
  incident_ids?: string[];
  replay_interval_seconds?: number;
}

export function DemoPage() {
  const { api, can } = useAuth();
  const { data, error, loading } = useApiQuery<{ scenarios: ScenarioInfo[]; replay_interval_seconds: number }>("/demo/scenarios");
  const [runs, setRuns] = useState<RunResult[]>([]);
  const [progress, setProgress] = useState<Record<string, number>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  useLiveEvents(["demo"], (message) => {
    const payload = message.data as { run_id?: string; released?: number } | null;
    if (payload?.run_id && typeof payload.released === "number") {
      setProgress((current) => ({ ...current, [payload.run_id as string]: payload.released as number }));
    }
  });

  async function start(scenario: string, mode: "instant" | "replay") {
    setBusy(`${scenario}:${mode}`);
    setRunError(null);
    try {
      const result = await api.post<RunResult>("/demo/run", { scenario, mode });
      setRuns((current) => [result, ...current].slice(0, 10));
    } catch (err) {
      setRunError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section>
      <h1>Demo scenarios</h1>
      <p className="muted">
        Synthetic data only. Each run uses a unique asset suffix. Replay releases one step every {data?.replay_interval_seconds ?? "…"} seconds so
        correlation and predictions can be watched live.
      </p>
      <ErrorBanner error={error} />
      {runError && (
        <p role="alert" className="error">
          {runError}
        </p>
      )}
      {runs.length > 0 && (
        <Card title="Recent runs">
          <ul className="plain">
            {runs.map((run) => (
              <li key={run.run_id}>
                <strong>{run.scenario}</strong> ({run.mode}, suffix <span className="mono">{run.suffix}</span>)
                {run.mode === "replay" && (
                  <span className="muted">
                    {" "}
                    · released {progress[run.run_id] ?? 0}/{run.steps.length} steps
                  </span>
                )}
                {run.incident_ids && (
                  <span>
                    {" "}
                    · {run.incident_ids.length} incident(s){" "}
                    {run.incident_ids.map((id) => (
                      <Link key={id} to={`/incidents/${id}`} className="spaced">
                        {shortId(id)}
                      </Link>
                    ))}
                  </span>
                )}
                {run.mode === "replay" && (
                  <span>
                    {" "}
                    · <Link to="/incidents">watch incidents</Link>
                  </span>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}
      {loading && !data && <Loading />}
      <div className="scenario-grid">
        {data?.scenarios.map((scenario) => (
          <Card key={scenario.id} title={scenario.name}>
            <p className="small">{scenario.description}</p>
            <p className="muted small">
              {scenario.event_count} events in {scenario.steps.length} step(s) · expected {scenario.expected.incidents} incident(s)
              {scenario.expected.campaigns ? `, ${scenario.expected.campaigns} campaign(s)` : ""}
              {scenario.expected.rules.length ? ` · ${scenario.expected.rules.join(", ")}` : ""}
            </p>
            {can("ingest") ? (
              <div className="form-row">
                <button type="button" disabled={busy !== null} onClick={() => start(scenario.id, "instant")}>
                  Run instantly
                </button>
                <button type="button" className="ghost" disabled={busy !== null} onClick={() => start(scenario.id, "replay")}>
                  Replay live
                </button>
              </div>
            ) : (
              <p className="muted small">Your role cannot load scenarios.</p>
            )}
          </Card>
        ))}
      </div>
    </section>
  );
}
