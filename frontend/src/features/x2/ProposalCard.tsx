import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../core/auth";
import { ConfirmDialog } from "../../core/ConfirmDialog";
import { errorMessage, formatTime } from "../../core/format";
import { StatusBadge } from "../../core/ui";
import { ACTION_LABELS, type Proposal } from "./types";
import "../ai.css";

export const INJECTION_PHRASE = "I REVIEWED THE FLAGGED TEXT";

export function ProposalCardView({
  proposal,
  canApply,
  canDismiss,
  onApply,
  onDismiss,
}: {
  proposal: Proposal;
  canApply: boolean;
  canDismiss: boolean;
  onApply: (acknowledgeInjection: boolean) => Promise<void>;
  onDismiss: (reason: string) => Promise<void>;
}) {
  const [dialog, setDialog] = useState<"apply" | "dismiss" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      setDialog(null);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const details = Object.entries(proposal.payload).filter(([, value]) => value !== null && value !== "");
  return (
    <div className={proposal.injection_context ? "proposal injection" : "proposal"}>
      <div className="header-badges">
        <strong>{ACTION_LABELS[proposal.action] ?? proposal.action}</strong>
        <StatusBadge status={proposal.status} />
        <span className="badge">needs {proposal.required_permission}</span>
      </div>
      {proposal.injection_context && (
        <div className="danger-banner small">
          Drafted while instruction-like text was present in the evidence. Check that this change is justified by the evidence, not by the log text.
        </div>
      )}
      {proposal.target_type === "incident" && proposal.target_id && (
        <div className="small">
          Target: <Link to={`/incidents/${proposal.target_id}`}>incident {proposal.target_id.slice(0, 8)}</Link> (revision {proposal.target_revision})
        </div>
      )}
      <ul className="small plain">
        {details.map(([key, value]) => (
          <li key={key}>
            <span className="muted">{key}:</span> {String(value)}
          </li>
        ))}
      </ul>
      <div className="small">
        <span className="muted">Why:</span> {proposal.rationale}
      </div>
      <div className="small muted">
        {proposal.evidence_ids.length} cited event(s) · drafted by {proposal.created_by} · {formatTime(proposal.created_at)}
      </div>
      {proposal.decided_by && (
        <div className="small muted">
          {proposal.status.toLowerCase()} by {proposal.decided_by}
          {proposal.decision_note ? `: ${proposal.decision_note}` : ""}
        </div>
      )}
      {proposal.status === "PROPOSED" && (
        <div className="form-row">
          {canApply && (
            <button type="button" onClick={() => setDialog("apply")}>
              Review and apply
            </button>
          )}
          {canDismiss && (
            <button type="button" className="ghost" onClick={() => setDialog("dismiss")}>
              Dismiss
            </button>
          )}
          {!canApply && <span className="small muted">Your role cannot apply this proposal.</span>}
        </div>
      )}
      {dialog === "apply" && (
        <ConfirmDialog
          title={`Apply: ${ACTION_LABELS[proposal.action] ?? proposal.action}`}
          description={
            <p>
              This runs the normal AEGIS action under your identity and is audited as your decision. It fails if the target changed since the agent
              drafted it.
            </p>
          }
          phrase={proposal.injection_context ? INJECTION_PHRASE : undefined}
          confirmLabel="Apply as me"
          busy={busy}
          error={error}
          onCancel={() => setDialog(null)}
          onConfirm={() => void run(() => onApply(proposal.injection_context))}
        />
      )}
      {dialog === "dismiss" && (
        <ConfirmDialog
          title="Dismiss this proposal?"
          reasonLabel="Reason"
          confirmLabel="Dismiss"
          danger
          busy={busy}
          error={error}
          onCancel={() => setDialog(null)}
          onConfirm={({ reason }) => void run(() => onDismiss(reason))}
        />
      )}
    </div>
  );
}

export function ProposalCard({ proposal, onChanged }: { proposal: Proposal; onChanged: () => void }) {
  const { api, can } = useAuth();
  return (
    <ProposalCardView
      proposal={proposal}
      canApply={can(proposal.required_permission)}
      canDismiss={can("ai.use")}
      onApply={async (acknowledge) => {
        await api.post(`/agent/proposals/${proposal.id}/apply`, { acknowledge_injection: acknowledge });
        onChanged();
      }}
      onDismiss={async (reason) => {
        await api.post(`/agent/proposals/${proposal.id}/dismiss`, { reason });
        onChanged();
      }}
    />
  );
}
