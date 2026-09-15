import { useState, type ReactNode } from "react";

export interface ConfirmDialogProps {
  title: string;
  description?: ReactNode;
  /** When set, the operator must type this exact phrase before confirming. */
  phrase?: string;
  /** When set, a free-text reason of at least this many characters is required. */
  reasonLabel?: string;
  reasonMinLength?: number;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  error?: string | null;
  onConfirm: (input: { phrase: string; reason: string }) => void;
  onCancel: () => void;
  children?: ReactNode;
}

export function ConfirmDialog({
  title,
  description,
  phrase,
  reasonLabel,
  reasonMinLength = 3,
  confirmLabel,
  danger,
  busy,
  error,
  onConfirm,
  onCancel,
  children,
}: ConfirmDialogProps) {
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const phraseOk = phrase === undefined || typed.trim() === phrase;
  const reasonOk = reasonLabel === undefined || reason.trim().length >= reasonMinLength;

  return (
    <div className="modal-backdrop">
      <div role="dialog" aria-modal="true" aria-labelledby="confirm-dialog-title" className="modal">
        <h2 id="confirm-dialog-title">{title}</h2>
        {description && <div className="muted">{description}</div>}
        {children}
        {reasonLabel !== undefined && (
          <label className="field">
            {reasonLabel}
            <textarea aria-label={reasonLabel} value={reason} onChange={(event) => setReason(event.target.value)} rows={3} />
          </label>
        )}
        {phrase !== undefined && (
          <label className="field">
            <span>
              Type <code>{phrase}</code> to confirm
            </span>
            <input
              aria-label="Confirmation phrase"
              value={typed}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setTyped(event.target.value)}
            />
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
            className={danger ? "danger" : undefined}
            disabled={!phraseOk || !reasonOk || busy}
            onClick={() => onConfirm({ phrase: typed.trim(), reason: reason.trim() })}
          >
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
