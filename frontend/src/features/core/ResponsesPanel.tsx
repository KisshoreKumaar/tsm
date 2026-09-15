import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../core/auth";
import { ConfirmDialog } from "../../core/ConfirmDialog";
import { errorMessage, formatTime, shortId } from "../../core/format";
import { JsonBlock, StatusBadge } from "../../core/ui";
import type { ResponseRecord } from "./types";

type Action = { kind: "approve" | "reject" | "execute"; response: ResponseRecord };

export function ResponsesPanel({
  responses,
  phrase,
  onChanged,
  showIncident = false,
}: {
  responses: ResponseRecord[];
  phrase: string;
  onChanged: () => void;
  showIncident?: boolean;
}) {
  const { api, can, principal } = useAuth();
  const [action, setAction] = useState<Action | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(input: { phrase: string; reason: string }) {
    if (!action) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const base = `/responses/${action.response.id}`;
      if (action.kind === "approve") {
        await api.post(`${base}/approve`, { confirmation: input.phrase });
      } else if (action.kind === "reject") {
        await api.post(`${base}/reject`, { reason: input.reason });
      } else {
        await api.post(`${base}/execute`, {});
      }
      setAction(null);
      onChanged();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (responses.length === 0) {
    return <p className="muted">No response requests.</p>;
  }

  return (
    <>
      <table className="table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Playbook</th>
            {showIncident && <th>Incident</th>}
            <th>Requested</th>
            <th>Decision</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {responses.map((response) => (
            <tr key={response.id}>
              <td>
                <StatusBadge status={response.approval_expired ? "EXPIRED" : response.status} />
              </td>
              <td>
                <strong>{response.playbook_name}</strong>
                <div className="muted small">
                  {response.asset} · {response.rationale}
                </div>
                {response.result && (
                  <details>
                    <summary>Simulation result</summary>
                    <JsonBlock value={response.result} />
                  </details>
                )}
              </td>
              {showIncident && (
                <td>
                  <Link to={`/incidents/${response.incident_id}`}>{shortId(response.incident_id)}</Link>
                </td>
              )}
              <td className="small">
                {response.requested_by}
                <div className="muted">{formatTime(response.requested_at)}</div>
              </td>
              <td className="small">
                {response.approved_by && <div>Approved by {response.approved_by}</div>}
                {response.expires_at && response.status === "APPROVED" && <div className="muted">Expires {formatTime(response.expires_at)}</div>}
                {response.executed_by && <div>Executed by {response.executed_by}</div>}
                {response.close_reason && <div className="muted">{response.close_reason}</div>}
              </td>
              <td className="actions">
                {response.status === "PENDING" && can("respond.approve") && (
                  <button type="button" onClick={() => setAction({ kind: "approve", response })}>
                    Approve
                  </button>
                )}
                {response.status === "APPROVED" && !response.approval_expired && can("respond.execute") && (
                  <button type="button" className="danger" onClick={() => setAction({ kind: "execute", response })}>
                    Execute simulation
                  </button>
                )}
                {(response.status === "PENDING" || response.status === "APPROVED") && can("respond.approve") && (
                  <button type="button" className="ghost" onClick={() => setAction({ kind: "reject", response })}>
                    Reject
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {action && (
        <ConfirmDialog
          title={
            action.kind === "approve"
              ? `Approve ${action.response.playbook_name}?`
              : action.kind === "execute"
                ? `Execute ${action.response.playbook_name}?`
                : "Reject this request?"
          }
          description={
            <>
              <p>
                Asset <strong>{action.response.asset}</strong>, bound to incident revision {action.response.incident_revision}.
                This is a simulation: only the virtual endpoint registry changes.
              </p>
              {action.kind === "approve" && <p>Approval expires after 15 minutes and is cancelled if the incident changes.</p>}
              {principal && action.response.requested_by === principal.name && action.kind !== "reject" && (
                <p className="warn">You requested this action. With the two-person rule enabled, another operator must decide.</p>
              )}
            </>
          }
          phrase={action.kind === "approve" ? phrase : undefined}
          reasonLabel={action.kind === "reject" ? "Reason for rejection" : undefined}
          confirmLabel={action.kind === "approve" ? "Approve" : action.kind === "execute" ? "Execute simulation" : "Reject"}
          danger={action.kind !== "approve"}
          busy={busy}
          error={error}
          onConfirm={run}
          onCancel={() => {
            setAction(null);
            setError(null);
          }}
        />
      )}
    </>
  );
}
