import { useAuth } from "../../core/auth";
import { Card, EmptyState, ErrorBanner, Loading } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import type { HitRate } from "../f4/types";
import type { FalsePositiveAnalytics } from "../a5/types";
import type { AiStatus } from "../x1/types";

interface Overview {
  metrics: { events_24h: number; detections_active: number; highest_open_risk: number; isolated_endpoints: number };
  open_incidents_by_severity: Record<string, number>;
  responses_by_status: Record<string, number>;
}

const percent = (value: number | null | undefined) => (value === null || value === undefined ? "—" : `${Math.round(value * 100)}%`);

export function MetricsPage() {
  const { principal } = useAuth();
  const has = (id: string) => principal?.features.some((feature) => feature.id === id) ?? false;
  const overview = useApiQuery<Overview>("/overview");
  const predictions = useApiQuery<HitRate>(has("f4") ? "/metrics/prediction-hit-rate" : null);
  const tuning = useApiQuery<FalsePositiveAnalytics>(has("a5") ? "/tuning/fp-analytics" : null, { days: 30 });
  const ai = useApiQuery<AiStatus>(has("x1") ? "/ai/status" : null);
  const rules = useApiQuery<{ items: { status: string }[] }>(has("a3") ? "/rules/custom" : null);
  const reports = useApiQuery<{ items: { status: string; deadline: { overdue: boolean } }[] }>(
    has("i1") ? "/cert-in" : null,
  );

  const activeRules = rules.data?.items.filter((rule) => rule.status === "ACTIVE").length ?? 0;
  const overdue = reports.data?.items.filter((report) => report.deadline.overdue && report.status !== "MARKED_SUBMITTED").length ?? 0;

  return (
    <section>
      <h1>Metrics</h1>
      <p className="muted">
        How AEGIS is doing on the data it holds. Every figure here is descriptive: counts and shares of AEGIS records,
        not accuracy against ground truth. The scenario evaluation (<span className="mono">make eval</span>) checks the
        same pipeline against expected outcomes.
      </p>
      <ErrorBanner error={overview.error} />
      {overview.loading && !overview.data && <Loading />}
      {overview.data && (
        <div className="tiles">
          <div className="tile">
            <div className="tile-value">{overview.data.metrics.events_24h}</div>
            <div className="tile-label">Events (24 h)</div>
          </div>
          <div className="tile">
            <div className="tile-value">{overview.data.metrics.detections_active}</div>
            <div className="tile-label">Active detections</div>
          </div>
          <div className="tile">
            <div className="tile-value">{overview.data.metrics.highest_open_risk}</div>
            <div className="tile-label">Highest open risk</div>
          </div>
          {predictions.data && (
            <div className="tile">
              <div className="tile-value">{percent(predictions.data.hit_rate)}</div>
              <div className="tile-label">Predictions observed</div>
            </div>
          )}
          {tuning.data && (
            <div className="tile">
              <div className="tile-value">{percent(tuning.data.false_positive_rate)}</div>
              <div className="tile-label">False positives (closed)</div>
            </div>
          )}
          {ai.data && (
            <div className="tile">
              <div className="tile-value">{percent(ai.data.grounding_rate)}</div>
              <div className="tile-label">AI claims cited</div>
            </div>
          )}
          {rules.data && (
            <div className="tile">
              <div className="tile-value">{activeRules}</div>
              <div className="tile-label">Active custom rules</div>
            </div>
          )}
          {reports.data && (
            <div className="tile">
              <div className="tile-value">{overdue}</div>
              <div className="tile-label">Reports past deadline</div>
            </div>
          )}
        </div>
      )}

      <div className="grid-2">
        {predictions.data && (
          <Card title="Prediction watchlist">
            <table className="table compact">
              <tbody>
                <tr>
                  <td>Observed</td>
                  <td>{predictions.data.observed}</td>
                </tr>
                <tr>
                  <td>Watching</td>
                  <td>{predictions.data.watching}</td>
                </tr>
                <tr>
                  <td>Expired</td>
                  <td>{predictions.data.expired}</td>
                </tr>
                <tr>
                  <td>Observed of resolved</td>
                  <td>{percent(predictions.data.resolved_hit_rate)}</td>
                </tr>
              </tbody>
            </table>
            <p className="hint">{predictions.data.label}</p>
          </Card>
        )}
        {ai.data && (
          <Card title="AI">
            <table className="table compact">
              <tbody>
                <tr>
                  <td>Mode</td>
                  <td>{ai.data.enabled ? `LLM (${ai.data.active_provider?.model ?? "provider set"})` : "Deterministic"}</td>
                </tr>
                <tr>
                  <td>Calls</td>
                  <td>{ai.data.calls}</td>
                </tr>
                <tr>
                  <td>Cache hits</td>
                  <td>{percent(ai.data.cache_hit_rate)}</td>
                </tr>
                <tr>
                  <td>Deterministic fallbacks</td>
                  <td>{ai.data.fallback_count}</td>
                </tr>
                <tr>
                  <td>Injection corpus</td>
                  <td>{percent(ai.data.injection_detector_pass_rate)}</td>
                </tr>
              </tbody>
            </table>
            <p className="hint">AI never writes: outputs are drafts a human applies.</p>
          </Card>
        )}
        {tuning.data && (
          <Card title="False positives by rule">
            <table className="table compact">
              <tbody>
                {tuning.data.per_rule.slice(0, 6).map((row) => (
                  <tr key={row.rule_id}>
                    <td className="mono">{row.rule_id}</td>
                    <td>
                      {row.false_positives}/{row.incidents}
                    </td>
                    <td className="muted">{percent(row.rate)}</td>
                  </tr>
                ))}
                {tuning.data.per_rule.length === 0 && (
                  <tr>
                    <td className="muted">No incidents yet.</td>
                  </tr>
                )}
              </tbody>
            </table>
            <p className="hint">{tuning.data.label}</p>
          </Card>
        )}
        {!predictions.data && !ai.data && !tuning.data && (
          <EmptyState>Enable F4, A5 or X1 to see prediction, tuning and AI metrics here.</EmptyState>
        )}
      </div>
    </section>
  );
}
