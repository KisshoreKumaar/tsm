import { useState } from "react";
import { useAuth } from "../../core/auth";
import { ConfirmDialog } from "../../core/ConfirmDialog";
import { errorMessage, formatTime } from "../../core/format";
import { EmptyState, StatusBadge } from "../../core/ui";
import type { SuppressionsResponse } from "./types";
import "./tuning.css";

export function remaining(seconds: number): string {
  if (seconds <= 0) return "expired";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  if (days > 0) return `${days} d ${hours} h`;
  if (hours > 0) return `${hours} h ${minutes} m`;
  return `${minutes} m`;
}

export function SuppressionsTable({ data, onChanged }: { data: SuppressionsResponse; onChanged: () => void }) {
  const { api, can } = useAuth();
  const [reverting, setReverting] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (data.items.length === 0 && data.parameter_overrides.length === 0) {
    return <EmptyState>No suppressions or parameter changes have been approved.</EmptyState>;
  }

  return (
    <>
      {data.items.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Scope</th>
              <th>Status</th>
              <th>Expires</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.items.map((suppression) => (
              <tr key={suppression.id}>
                <td className="mono">{suppression.rule_id}</td>
                <td className="small">
                  {suppression.entities.map((entity) => `${entity.type} ${entity.value}`).join(", ") || "whole rule"}
                  {suppression.schedule && (
                    <div className="muted">
                      days {suppression.schedule.days.join(", ")} · {suppression.schedule.start}–{suppression.schedule.end} UTC
                    </div>
                  )}
                </td>
                <td>
                  <StatusBadge status={suppression.status} />
                </td>
                <td className={suppression.applies && suppression.seconds_remaining < 86_400 ? "expiry soon" : "expiry"}>
                  {suppression.applies ? remaining(suppression.seconds_remaining) : formatTime(suppression.ended_at ?? suppression.expires_at)}
                </td>
                <td>
                  {suppression.applies && can("tuning.approve") && (
                    <button type="button" className="link" onClick={() => setReverting(suppression.id)}>
                      revert
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data.parameter_overrides.length > 0 && (
        <table className="table compact">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Parameters</th>
              <th>Previously</th>
              <th>Status</th>
              <th>Applied</th>
            </tr>
          </thead>
          <tbody>
            {data.parameter_overrides.map((override) => (
              <tr key={override.id}>
                <td className="mono">{override.rule_id}</td>
                <td className="small mono">{JSON.stringify(override.parameters)}</td>
                <td className="small mono muted">{JSON.stringify(override.previous)}</td>
                <td>
                  <StatusBadge status={override.status} />
                </td>
                <td className="small muted">
                  {override.created_by} · {formatTime(override.created_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="hint">Parameter changes are reverted from their tuning suggestion, which keeps the audit trail together.</p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {reverting && (
        <ConfirmDialog
          title="Revert this suppression?"
          description="Suppressed detections become active again and the affected incidents are re-evaluated."
          reasonLabel="Reason"
          confirmLabel="Revert"
          danger
          busy={busy}
          error={error}
          onCancel={() => setReverting(null)}
          onConfirm={({ reason }) => {
            setBusy(true);
            setError(null);
            void api
              .post(`/suppressions/${reverting}/revert`, { reason })
              .then(() => {
                setReverting(null);
                onChanged();
              })
              .catch((err: unknown) => setError(errorMessage(err)))
              .finally(() => setBusy(false));
          }}
        />
      )}
    </>
  );
}
