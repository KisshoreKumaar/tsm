import { useEffect } from "react";
import { Card, ErrorBanner, Loading } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import type { AiStatus } from "./types";

const percent = (value: number | null) => (value === null ? "—" : `${Math.round(value * 100)}%`);

export function AiStatusPage() {
  const { data, error, loading, refetch } = useApiQuery<AiStatus>("/ai/status");
  useEffect(() => {
    const timer = window.setInterval(refetch, 15_000);
    return () => window.clearInterval(timer);
  }, [refetch]);

  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBanner error={error} />;

  const tiles: [string, string | number][] = [
    ["Mode", data.enabled ? "LLM" : "Deterministic"],
    ["Model", data.active_provider ? data.active_provider.model : "—"],
    ["Measured tokens/s", data.measured_tokens_per_second ?? "—"],
    ["Avg latency", data.average_latency_ms ? `${(data.average_latency_ms / 1000).toFixed(1)} s` : "—"],
    ["Queue", `${data.queue.queued} queued · ${data.queue.running} running`],
    ["Cache hit rate", percent(data.cache_hit_rate)],
    ["Grounding rate", percent(data.grounding_rate)],
    ["Fallbacks", data.fallback_count],
    ["Injection detector", percent(data.injection_detector_pass_rate)],
  ];

  return (
    <section>
      <h1>AI status</h1>
      <div className="tiles">
        {tiles.map(([label, value]) => (
          <div key={label} className="tile">
            <div className="tile-value">{value}</div>
            <div className="tile-label">{label}</div>
          </div>
        ))}
      </div>
      <Card title="Recent outcomes">
        <table className="table compact">
          <tbody>
            {Object.entries(data.outcomes).map(([outcome, count]) => (
              <tr key={outcome}>
                <td className="mono">{outcome}</td>
                <td>{count}</td>
              </tr>
            ))}
            {Object.keys(data.outcomes).length === 0 && (
              <tr>
                <td className="muted">No AI calls yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
      {data.active_provider && (
        <p className="hint">
          Active provider {data.active_provider.name} ({data.active_provider.source}); redaction {data.active_provider.redact ? "on" : "off"}.
        </p>
      )}
      {data.notes.map((note) => (
        <p key={note} className="hint">
          {note}
        </p>
      ))}
    </section>
  );
}
