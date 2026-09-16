import { useState } from "react";
import { useAuth } from "../../core/auth";
import { errorMessage, formatTime } from "../../core/format";
import { Card, EmptyState, ErrorBanner, Loading, StatusBadge } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import type { IncidentTabProps } from "../core/incidentTabTypes";
import { DeadlineBadge } from "./DeadlineBadge";
import type { CertInReport, ReportDiff, ReportField } from "./types";
import "./compliance.css";

const EDITABLE: Record<string, boolean> = { description: true, impact_assessment: true, reporter_notes: true };

function SubmittedDialog({
  busy,
  error,
  onCancel,
  onConfirm,
}: {
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: (input: { submitted_at: string; reference: string; note: string | null }) => void;
}) {
  const [when, setWhen] = useState("");
  const [reference, setReference] = useState("");
  const [note, setNote] = useState("");
  const ready = when.trim().length > 0 && reference.trim().length > 0;
  return (
    <div className="modal-backdrop">
      <div role="dialog" aria-modal="true" aria-labelledby="submitted-title" className="modal">
        <h2 id="submitted-title">Record the submission</h2>
        <p className="muted">
          AEGIS does not send anything. File the report through the official channel, then record when you sent it and
          the reference you were given.
        </p>
        <label className="field">
          Submitted at (UTC)
          <input
            type="datetime-local"
            aria-label="Submitted at (UTC)"
            value={when}
            onChange={(event) => setWhen(event.target.value)}
          />
        </label>
        <label className="field">
          Reference number
          <input aria-label="Reference number" maxLength={120} value={reference} onChange={(event) => setReference(event.target.value)} />
        </label>
        <label className="field">
          Note (optional)
          <input aria-label="Submission note" maxLength={500} value={note} onChange={(event) => setNote(event.target.value)} />
        </label>
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
              onConfirm({ submitted_at: `${when}:00Z`.replace(/:\d\d:00Z$/, ":00Z"), reference: reference.trim(), note: note.trim() || null })
            }
          >
            {busy ? "Saving…" : "Mark as submitted"}
          </button>
        </div>
      </div>
    </div>
  );
}

function FieldRow({
  field,
  editable,
  onCite,
  onSave,
}: {
  field: ReportField;
  editable: boolean;
  onCite: (ids: string[]) => void;
  onSave: (value: string) => Promise<void>;
}) {
  const [draft, setDraft] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="report-field">
      <div className="header-badges">
        <strong>{field.label}</strong>
        <span className={`badge provenance-${field.provenance}`}>{field.provenance}</span>
        {field.evidence_ids.length > 0 && (
          <button type="button" className="link" onClick={() => onCite(field.evidence_ids)}>
            {field.evidence_ids.length} evidence event(s)
          </button>
        )}
        {field.refs.length > 0 && <span className="muted small">{field.refs.map((ref) => ref.type).join(", ")}</span>}
      </div>
      {draft === null ? (
        <div className="value small">{field.value || <em className="muted">Not filled in</em>}</div>
      ) : (
        <textarea aria-label={field.label} rows={4} value={draft} onChange={(event) => setDraft(event.target.value)} />
      )}
      {field.note && <div className="hint">{field.note}</div>}
      {editable && (
        <div className="form-row">
          {draft === null ? (
            <button type="button" className="link" onClick={() => setDraft(field.value)}>
              Edit
            </button>
          ) : (
            <>
              <button
                type="button"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await onSave(draft);
                    setDraft(null);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Save
              </button>
              <button type="button" className="ghost" onClick={() => setDraft(null)}>
                Cancel
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export function ReportEditor({ incident, onCite }: IncidentTabProps) {
  const { api, can } = useAuth();
  const { data, error, loading, refetch } = useApiQuery<CertInReport>(`/incidents/${incident.id}/cert-in`, {
    revision: incident.revision,
  });
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [dialog, setDialog] = useState(false);
  const [exported, setExported] = useState<string | null>(null);
  const [diff, setDiff] = useState<ReportDiff | null>(null);

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setActionError(null);
    try {
      await action();
      refetch();
    } catch (err) {
      setActionError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (loading && !data) return <Loading />;
  if (!data) {
    const missing = error instanceof Error && "status" in error && (error as { status?: number }).status === 404;
    return (
      <Card title="CERT-In report draft">
        {missing ? (
          <>
            <p className="hint">
              AEGIS can prepare a CERT-In draft from this incident&apos;s evidence: detection and occurrence times,
              affected systems, indicators, techniques and the actions recorded here. A human reviews, approves and
              files it; AEGIS never transmits anything.
            </p>
            {can("reports.draft") ? (
              <button type="button" disabled={busy} onClick={() => void run(() => api.post(`/incidents/${incident.id}/cert-in`, {}))}>
                {busy ? "Preparing…" : "Prepare CERT-In draft"}
              </button>
            ) : (
              <p className="muted">Your role cannot prepare compliance drafts.</p>
            )}
            {actionError && (
              <p role="alert" className="error">
                {actionError}
              </p>
            )}
          </>
        ) : (
          <ErrorBanner error={error} />
        )}
      </Card>
    );
  }

  const canEdit = can("reports.draft") && data.allowed_actions.includes("edit");
  return (
    <div>
      <Card
        title={
          <>
            CERT-In report draft <StatusBadge status={data.status} /> <span className="muted small">v{data.version}</span>
          </>
        }
        actions={<DeadlineBadge deadline={data.deadline} />}
      >
        {data.template.banner && <div className="warning-banner small">{data.template.banner}</div>}
        <p className="hint">{data.never_transmits}</p>
        {data.stale && (
          <div className="warning-banner small">
            The incident changed since this draft (revision {data.incident_revision}); regenerate before filing.
          </div>
        )}
        <p className="small">
          <span className="muted">Suggested type:</span> {data.reportability.incident_type_label} (
          {data.reportability.reportable}, {data.reportability.confidence} confidence).{" "}
          <span className="muted">{data.reportability.label}</span>
        </p>
        <ul className="plain small muted">
          {data.reportability.reasons.slice(0, 4).map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
        {data.completeness.missing_required.length > 0 && (
          <div className="small">
            <span className="muted">Still required:</span>
            <span className="missing-list">
              {data.completeness.missing_required.map((id) => (
                <span key={id} className="badge provenance-missing">
                  {id.replaceAll("_", " ")}
                </span>
              ))}
            </span>
          </div>
        )}
        <div className="form-row">
          {can("reports.draft") && data.allowed_actions.includes("regenerate") && (
            <button type="button" className="ghost" disabled={busy} onClick={() => void run(() => api.post(`/incidents/${incident.id}/cert-in`, {}))}>
              Regenerate from evidence
            </button>
          )}
          {can("reports.draft") && data.allowed_actions.includes("submit_review") && (
            <button type="button" disabled={busy} onClick={() => void run(() => api.post(`/cert-in/${data.id}/submit-review`, {}))}>
              Send for review
            </button>
          )}
          {can("reports.finalize") && data.allowed_actions.includes("approve") && (
            <button type="button" disabled={busy} onClick={() => void run(() => api.post(`/cert-in/${data.id}/approve`, {}))}>
              Approve
            </button>
          )}
          {can("reports.finalize") && data.allowed_actions.includes("mark_submitted") && (
            <button type="button" disabled={busy} onClick={() => setDialog(true)}>
              Mark as submitted
            </button>
          )}
          {(["md", "json", "html"] as const).map((format) => (
            <button
              key={format}
              type="button"
              className="ghost"
              onClick={() => void run(async () => setExported(await api.text(`/cert-in/${data.id}/export`, { format })))}
            >
              Export {format}
            </button>
          ))}
          <button
            type="button"
            className="ghost"
            onClick={() => void run(async () => setExported(await api.text(`/cert-in/${data.id}/export`, { format: "md", redact: true })))}
          >
            Export redacted
          </button>
        </div>
        {data.two_person && <p className="hint">Two-person mode: the approver must differ from the person who prepared the draft.</p>}
        {data.submitted_at && (
          <p className="small">
            Recorded as submitted by {data.submitted_by} at {formatTime(data.submitted_at)} · reference{" "}
            <span className="mono">{data.submission_reference}</span>
          </p>
        )}
        {actionError && (
          <p role="alert" className="error">
            {actionError}
          </p>
        )}
        {exported && (
          <pre className="json" aria-label="Report export">
            {exported}
          </pre>
        )}
      </Card>

      <Card title="Fields">
        {data.fields.map((field) => (
          <FieldRow
            key={field.id}
            field={field}
            editable={canEdit && Boolean(EDITABLE[field.id])}
            onCite={onCite}
            onSave={(value) => api.patch(`/cert-in/${data.id}`, { fields: { [field.id]: value } }).then(() => refetch())}
          />
        ))}
      </Card>

      {data.versions.length > 1 && (
        <Card title="Versions">
          <table className="table compact">
            <tbody>
              {data.versions.map((version) => (
                <tr key={version.version}>
                  <td className="mono">v{version.version}</td>
                  <td className="small">{version.note ?? "—"}</td>
                  <td className="small muted">
                    {version.created_by} · {formatTime(version.created_at)}
                    {version.ai_status ? ` · AI ${version.ai_status}` : ""}
                  </td>
                  <td>
                    {version.version > 1 && (
                      <button
                        type="button"
                        className="link"
                        onClick={() =>
                          void run(async () =>
                            setDiff(
                              await api.get<ReportDiff>(`/cert-in/${data.id}/diff`, {
                                from_version: version.version - 1,
                                to_version: version.version,
                              }),
                            ),
                          )
                        }
                      >
                        diff with v{version.version - 1}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {diff && (
            <div className="small">
              {diff.changes.length === 0 ? (
                <EmptyState>No field changed between these versions.</EmptyState>
              ) : (
                diff.changes.map((change) => (
                  <div key={change.field} className="report-field">
                    <strong>{change.label}</strong>
                    <div className="muted">
                      {change.old_provenance} → {change.new_provenance}
                    </div>
                    <div className="value">{change.new}</div>
                  </div>
                ))
              )}
            </div>
          )}
        </Card>
      )}

      {dialog && (
        <SubmittedDialog
          busy={busy}
          error={actionError}
          onCancel={() => setDialog(false)}
          onConfirm={(input) => {
            setDialog(false);
            void run(() => api.post(`/cert-in/${data.id}/mark-submitted`, input));
          }}
        />
      )}
    </div>
  );
}
