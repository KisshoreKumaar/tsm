import { Link } from "react-router-dom";
import { formatTime } from "../../core/format";
import type { BacktestResult } from "./types";
import "./rules.css";

export function BacktestView({ result }: { result: BacktestResult }) {
  const tiles: [string, string | number][] = [
    ["Alerts", result.detections],
    ["Matching events", result.total_matches],
    ["New incidents", result.incidents_that_would_be_created],
    ["Existing incidents", result.existing_incidents_matched],
    ["In false positives", result.matches_in_false_positive_incidents],
    ["In benign data", result.matches_in_benign_scenario],
    ["Alerts per day", result.estimated_alerts_per_day],
    ["Events scanned", result.events_scanned],
  ];
  const overlap = Object.entries(result.overlap_with_existing_rules);
  return (
    <div>
      <div className="backtest-grid">
        {tiles.map(([label, value]) => (
          <div key={label} className="tile">
            <div className="tile-value">{value}</div>
            <div className="tile-label">{label}</div>
          </div>
        ))}
      </div>
      <p className="hint">
        {formatTime(result.range.start)} to {formatTime(result.range.end)} · {result.runtime_ms} ms. {result.label}
        {result.truncated && " The range hit the scan limit, so figures are partial."}
      </p>
      {result.matches_in_benign_scenario > 0 && (
        <div className="warning-banner small">
          This rule also fires {result.matches_in_benign_scenario} time(s) on the synthetic benign workday; expect
          false positives.
        </div>
      )}
      {overlap.length > 0 && (
        <p className="small">
          <span className="muted">Overlaps with:</span>{" "}
          {overlap.map(([ruleId, count]) => `${ruleId} (${count})`).join(", ")}
        </p>
      )}
      {result.sample_hits.length > 0 && (
        <table className="table compact">
          <thead>
            <tr>
              <th>When</th>
              <th>Hit</th>
              <th>Incident</th>
            </tr>
          </thead>
          <tbody>
            {result.sample_hits.map((hit) => (
              <tr key={`${hit.first_ts}-${hit.event_ids[0] ?? ""}`}>
                <td className="nowrap">{formatTime(hit.first_ts)}</td>
                <td className="small">{hit.summary}</td>
                <td className="small">
                  {hit.incident_ids.length === 0
                    ? "would create one"
                    : hit.incident_ids.map((id) => (
                        <Link key={id} to={`/incidents/${id}`} className="mono">
                          {id.slice(0, 8)}{" "}
                        </Link>
                      ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
