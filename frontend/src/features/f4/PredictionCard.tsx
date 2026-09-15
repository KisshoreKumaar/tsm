import { formatTime } from "../../core/format";
import { ClaimLabel, StatusBadge } from "../../core/ui";
import type { ExplanationItem, Prediction } from "./types";
import "./prediction.css";

export const LIKELIHOOD_HINT = "Relative likelihood score for ranking hypotheses. It is a heuristic, not a probability.";

export function horizonText(seconds: number): string {
  if (seconds >= 3600) {
    const hours = seconds / 3600;
    return `${Number.isInteger(hours) ? hours : hours.toFixed(1)} h`;
  }
  return `${Math.round(seconds / 60)} min`;
}

export function PredictionCard({
  prediction,
  rank,
  onCite,
  explanation,
}: {
  prediction: Prediction;
  rank: number;
  onCite: (eventIds: string[]) => void;
  explanation?: ExplanationItem;
}) {
  const { technique } = prediction;
  return (
    <article className={`prediction ${prediction.status.toLowerCase()}`} aria-label={`Prediction ${technique.id}`}>
      <div className="prediction-head">
        <span className="prediction-rank">#{rank}</span>
        <a className="technique" href={technique.url} target="_blank" rel="noreferrer noopener">
          {technique.id} {technique.name}
        </a>
        <span className="badge">{technique.tactic}</span>
        <ClaimLabel label={prediction.label} />
        <StatusBadge status={prediction.status} />
        <span className="likelihood" title={LIKELIHOOD_HINT}>
          Likelihood {prediction.score}/100 · {prediction.band}
        </span>
      </div>
      <div className="likelihood-bar" aria-hidden="true">
        <span style={{ width: `${prediction.score}%` }} />
      </div>
      <p className="small">{prediction.rationale}</p>
      {explanation && (
        <p className="small">
          <span className="badge">AI explanation</span> {explanation.text}
          {explanation.evidence_ids.length > 0 && (
            <button type="button" className="link" onClick={() => onCite(explanation.evidence_ids)}>
              cited evidence ({explanation.evidence_ids.length})
            </button>
          )}
        </p>
      )}
      <div className="small">
        {prediction.status === "OBSERVED" && prediction.observed_at ? (
          <>
            <strong>Observed</strong> at {formatTime(prediction.observed_at)}.{" "}
            <button type="button" className="link" onClick={() => onCite(prediction.observed_event_ids)}>
              show observed evidence ({prediction.observed_event_ids.length})
            </button>
          </>
        ) : prediction.status === "EXPIRED" ? (
          <>
            Not observed within {horizonText(prediction.horizon_seconds)}; expired {formatTime(prediction.expires_at)}.
          </>
        ) : (
          <>
            Watching until {formatTime(prediction.expires_at)} (heuristic horizon {horizonText(prediction.horizon_seconds)}).
          </>
        )}{" "}
        <button type="button" className="link" onClick={() => onCite(prediction.evidence_ids)}>
          basis evidence ({prediction.evidence_ids.length})
        </button>
      </div>
      <div className="small">
        <span className="muted">Watch for:</span>
        <ul className="plain">
          {prediction.watch_signals.map((signal) => (
            <li key={signal.text}>
              <span className="mono">{signal.text}</span> <span className="muted">— {signal.description}</span>
            </li>
          ))}
        </ul>
      </div>
      {prediction.preventive_actions.length > 0 && (
        <div className="small">
          <span className="muted">Preventive steps (you decide; nothing runs automatically):</span>
          <ul className="plain">
            {prediction.preventive_actions.map((action) => (
              <li key={action.text}>
                {action.text}
                {action.playbook && <span className="muted"> · simulated playbook {action.playbook}, requires approval</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      <details>
        <summary>Score factors</summary>
        <table className="table compact">
          <tbody>
            {prediction.factors.map((factor) => (
              <tr key={factor.name}>
                <td>{factor.label}</td>
                <td className="nowrap">
                  {factor.points}/{factor.max_points}
                </td>
                <td className="muted small">{factor.explanation}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="hint">{LIKELIHOOD_HINT}</p>
      </details>
    </article>
  );
}
