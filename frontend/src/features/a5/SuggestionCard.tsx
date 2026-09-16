import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../core/auth";
import { ConfirmDialog } from "../../core/ConfirmDialog";
import { errorMessage, formatTime } from "../../core/format";
import { StatusBadge } from "../../core/ui";
import type { ApprovalInput, Suggestion } from "./types";
import "./tuning.css";

const TYPE_LABELS: Record<string, string> = {
  suppression: "Scoped suppression",
  maintenance_window: "Maintenance window",
  threshold: "Threshold change",
  window: "Window change",
  dsl_exclusion: "Exclusion condition",
};

export function describeScope(suggestion: Suggestion): string {
  const { scope } = suggestion;
  const parts = (scope.entities ?? []).map((entity) => `${entity.type} ${entity.value}`);
  if (scope.schedule) {
    parts.push(`days ${scope.schedule.days.join(", ")} ${scope.schedule.start}–${scope.schedule.end} UTC`);
  }
  if (scope.threshold != null) parts.push(`threshold ${scope.threshold}`);
  if (scope.window_seconds != null) parts.push(`window ${scope.window_seconds}s`);
  if (scope.exclusion) parts.push(`exclude ${scope.exclusion.field} ${scope.exclusion.op} ${String(scope.exclusion.value)}`);
  return parts.join(" · ") || "the whole rule";
}

function ApproveDialog({
  suggestion,
  busy,
  error,
  onCancel,
  onConfirm,
}: {
  suggestion: Suggestion;
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: (input: ApprovalInput) => void;
}) {
  const suppressive = suggestion.type === "suppression" || suggestion.type === "maintenance_window";
  const [days, setDays] = useState(suggestion.scope.expires_in_days ?? 30);
  const [ackProtected, setAckProtected] = useState(false);
  const [ackLoss, setAckLoss] = useState(false);
  const needsProtected = suggestion.requires.protected_rule_acknowledgement;
  const needsLoss = suggestion.requires.true_positive_loss_acknowledgement;
  const ready = (!needsProtected || ackProtected) && (!needsLoss || ackLoss);
  const removed = suggestion.impact?.true_positive_alerts_removed ?? 0;

  return (
    <div className="modal-backdrop">
      <div role="dialog" aria-modal="true" aria-labelledby="approve-tuning-title" className="modal">
        <h2 id="approve-tuning-title">Approve tuning change</h2>
        <p className="muted">
          {TYPE_LABELS[suggestion.type]} for {suggestion.rule_id} ({describeScope(suggestion)}). It applies under your
          identity, is audited, and can be reverted in one click.
        </p>
        {suppressive && (
          <label className="field">
            Expires in days (at most 90)
            <input
              type="number"
              min={1}
              max={90}
              aria-label="Expires in days"
              value={days}
              onChange={(event) => setDays(Number(event.target.value))}
            />
          </label>
        )}
        {needsProtected && (
          <label className="check">
            <input type="checkbox" checked={ackProtected} onChange={(event) => setAckProtected(event.target.checked)} />
            <span>{suggestion.rule_id} is a protected rule. I have reviewed this change.</span>
          </label>
        )}
        {needsLoss && (
          <label className="check">
            <input type="checkbox" checked={ackLoss} onChange={(event) => setAckLoss(event.target.checked)} />
            <span>
              This removes {removed} alert(s) from incidents that are not closed as false positives. I accept that.
            </span>
          </label>
        )}
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            type="button"
            disabled={!ready || busy}
            onClick={() =>
              onConfirm({
                ...(suppressive ? { expires_in_days: days } : {}),
                acknowledge_protected_rule: ackProtected,
                acknowledge_true_positive_loss: ackLoss,
              })
            }
          >
            {busy ? "Applying…" : "Approve and apply"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function SuggestionCardView({
  suggestion,
  canApprove,
  canDraft,
  onApprove,
  onReject,
  onSimulate,
  onRevert,
}: {
  suggestion: Suggestion;
  canApprove: boolean;
  canDraft: boolean;
  onApprove: (input: ApprovalInput) => Promise<void>;
  onReject: (reason: string) => Promise<void>;
  onSimulate: () => Promise<void>;
  onRevert: (reason: string) => Promise<void>;
}) {
  const [dialog, setDialog] = useState<"approve" | "reject" | "revert" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const impact = suggestion.impact;

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

  return (
    <article className={impact?.red_flag ? "suggestion red-flag" : "suggestion"} aria-label={`Suggestion ${suggestion.id}`}>
      <div className="header-badges">
        <strong>{TYPE_LABELS[suggestion.type] ?? suggestion.type}</strong>
        <span className="badge mono">{suggestion.rule_id}</span>
        <StatusBadge status={suggestion.status} />
        {suggestion.protected_rule && <span className="badge warn">protected rule</span>}
        {suggestion.ai_rank !== null && <span className="badge">AI rank {suggestion.ai_rank}</span>}
        <span className="muted small">{suggestion.source === "manual" ? "proposed by an analyst" : "found by AEGIS"}</span>
      </div>
      <div className="small">
        <span className="muted">Scope:</span> <span className="mono">{describeScope(suggestion)}</span>
      </div>
      <p className="small">{suggestion.rationale}</p>
      {suggestion.ai_rationale && (
        <p className="small">
          <span className="badge">AI</span> {suggestion.ai_rationale}
        </p>
      )}
      {impact ? (
        <>
          <div className="impact-grid small">
            <div>
              <span className="muted">Alerts removed</span>
              <div className="impact-value">{impact.alerts_removed}</div>
            </div>
            <div>
              <span className="muted">False positives</span>
              <div className="impact-value">{impact.false_positive_alerts_removed}</div>
            </div>
            <div>
              <span className="muted">True positives</span>
              <div className={impact.true_positive_alerts_removed ? "impact-value danger" : "impact-value"}>
                {impact.true_positive_alerts_removed}
              </div>
            </div>
            <div>
              <span className="muted">Incidents lost</span>
              <div className={impact.true_positives_lost ? "impact-value danger" : "impact-value"}>
                {impact.true_positives_lost}
              </div>
            </div>
          </div>
          {impact.red_flag && (
            <div className="danger-banner small">
              This change would also remove {impact.true_positive_alerts_removed} alert(s) from incidents that are not
              closed as false positives
              {impact.true_positive_incidents_affected.length > 0 && (
                <>
                  {": "}
                  {impact.true_positive_incidents_affected.slice(0, 3).map((id) => (
                    <Link key={id} to={`/incidents/${id}`} className="mono">
                      {id.slice(0, 8)}{" "}
                    </Link>
                  ))}
                </>
              )}
              . Approving needs an explicit acknowledgement.
            </div>
          )}
          <div className="muted small">
            {impact.label} Simulated {formatTime(suggestion.impact_at)}.
          </div>
        </>
      ) : (
        <p className="hint">No impact simulation yet.</p>
      )}
      {suggestion.status === "PROPOSED" && (
        <div className="form-row">
          {canApprove && (
            <button type="button" onClick={() => setDialog("approve")}>
              Review and approve
            </button>
          )}
          {canApprove && (
            <button type="button" className="ghost" onClick={() => setDialog("reject")}>
              Reject
            </button>
          )}
          {canDraft && (
            <button type="button" className="ghost" disabled={busy} onClick={() => void run(onSimulate)}>
              Re-simulate
            </button>
          )}
          {!canApprove && <span className="small muted">Your role can review tuning, but not approve it.</span>}
        </div>
      )}
      {suggestion.status === "APPROVED" && canApprove && (
        <div className="form-row">
          <button type="button" className="ghost" onClick={() => setDialog("revert")}>
            Revert
          </button>
          <span className="small muted">
            Applied by {suggestion.decided_by} · {formatTime(suggestion.decided_at)}
          </span>
        </div>
      )}
      {error && !dialog && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {dialog === "approve" && (
        <ApproveDialog
          suggestion={suggestion}
          busy={busy}
          error={error}
          onCancel={() => setDialog(null)}
          onConfirm={(input) => void run(() => onApprove(input))}
        />
      )}
      {dialog === "reject" && (
        <ConfirmDialog
          title="Reject this suggestion?"
          description="It stays in the history and AEGIS will not propose the same scope again."
          reasonLabel="Reason"
          confirmLabel="Reject"
          danger
          busy={busy}
          error={error}
          onCancel={() => setDialog(null)}
          onConfirm={({ reason }) => void run(() => onReject(reason))}
        />
      )}
      {dialog === "revert" && (
        <ConfirmDialog
          title="Revert this tuning change?"
          description="Suppressed detections become active again and the affected incidents are re-evaluated."
          reasonLabel="Reason"
          confirmLabel="Revert"
          danger
          busy={busy}
          error={error}
          onCancel={() => setDialog(null)}
          onConfirm={({ reason }) => void run(() => onRevert(reason))}
        />
      )}
    </article>
  );
}

export function SuggestionCard({ suggestion, onChanged }: { suggestion: Suggestion; onChanged: () => void }) {
  const { api, can } = useAuth();
  return (
    <SuggestionCardView
      suggestion={suggestion}
      canApprove={can("tuning.approve")}
      canDraft={can("tuning.draft")}
      onApprove={async (input) => {
        await api.post(`/tuning/suggestions/${suggestion.id}/approve`, input);
        onChanged();
      }}
      onReject={async (reason) => {
        await api.post(`/tuning/suggestions/${suggestion.id}/reject`, { reason });
        onChanged();
      }}
      onSimulate={async () => {
        await api.post(`/tuning/suggestions/${suggestion.id}/simulate`, {});
        onChanged();
      }}
      onRevert={async (reason) => {
        await api.post(`/tuning/suggestions/${suggestion.id}/revert`, { reason });
        onChanged();
      }}
    />
  );
}
