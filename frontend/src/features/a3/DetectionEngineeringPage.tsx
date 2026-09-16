import { useState } from "react";
import { useAuth } from "../../core/auth";
import { ConfirmDialog } from "../../core/ConfirmDialog";
import { errorMessage, formatTime } from "../../core/format";
import { Card, EmptyState, ErrorBanner, JsonBlock, Loading, SeverityBadge, StatusBadge } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import { BacktestView } from "./BacktestView";
import { ACTION_LABELS, ACTION_PERMISSION, blockedReason, latestBacktest, versionNote } from "./lifecycle";
import { RuleEditor } from "./RuleEditor";
import type { RuleAction, RuleDetail, RuleDiff, RuleStatus, RuleSummary } from "./types";
import "./rules.css";

const ACTIONS: RuleAction[] = ["backtest", "approve", "activate", "disable", "retire", "edit"];
const STATUSES: RuleStatus[] = ["DRAFT", "TESTED", "APPROVED", "ACTIVE", "DISABLED", "RETIRED"];

function RuleDetailView({ rule, onChanged }: { rule: RuleDetail; onChanged: () => void }) {
  const { api, can } = useAuth();
  const [dialog, setDialog] = useState<"disable" | "retire" | null>(null);
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exported, setExported] = useState<{ format: string; text: string } | null>(null);
  const [diff, setDiff] = useState<RuleDiff | null>(null);
  const backtest = latestBacktest(rule);

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      onChanged();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <Card
        title={
          <>
            <span className="mono">{rule.id}</span> {rule.name} <StatusBadge status={rule.status} />{" "}
            <SeverityBadge severity={rule.definition.severity} />
          </>
        }
        actions={<span className="small muted">v{rule.current_version} by {rule.current_version_author}</span>}
      >
        <p className="small">{rule.definition.description}</p>
        <p className="hint">{versionNote(rule)}</p>
        {rule.source !== "manual" && (
          <p className="hint">
            Drafted {rule.source === "ai_draft" ? "by the AI" : "deterministically"} from incident{" "}
            <span className="mono">{rule.source_incident_id?.slice(0, 8)}</span>. Review it before approval.
          </p>
        )}
        <div className="form-row">
          {ACTIONS.map((action) => {
            const reason = blockedReason(rule, action);
            const permitted = can(ACTION_PERMISSION[action]);
            return (
              <button
                key={action}
                type="button"
                className={action === "retire" || action === "disable" ? "ghost" : undefined}
                disabled={busy || !permitted || reason !== null}
                title={!permitted ? `Needs the ${ACTION_PERMISSION[action]} permission` : (reason ?? "")}
                onClick={() => {
                  if (action === "edit") return setEditing(true);
                  if (action === "disable" || action === "retire") return setDialog(action);
                  void run(() => api.post(`/rules/${rule.id}/${action}`, {}));
                }}
              >
                {ACTION_LABELS[action]}
              </button>
            );
          })}
        </div>
        {rule.two_person && (
          <p className="hint">Two-person mode is on: the approver must be someone other than the version&apos;s author.</p>
        )}
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
      </Card>

      {editing && (
        <Card title={`New version of ${rule.id}`}>
          <RuleEditor
            initial={rule.definition}
            submitLabel="Save version"
            onCancel={() => setEditing(false)}
            onSubmit={async (definition, rationale) => {
              await api.post(`/rules/${rule.id}/versions`, { definition, rationale });
              setEditing(false);
              onChanged();
            }}
          />
        </Card>
      )}

      <Card title="Definition">
        <JsonBlock value={rule.definition} />
        <div className="form-row">
          {(["json", "sigma"] as const).map((format) => (
            <button
              key={format}
              type="button"
              className="ghost"
              onClick={() =>
                void run(async () => {
                  const text = await api.text(`/rules/${rule.id}/export`, { format });
                  setExported({ format, text });
                })
              }
            >
              Show {format === "json" ? "JSON" : "Sigma"} export
            </button>
          ))}
        </div>
        {rule.sigma_warnings.length > 0 && (
          <p className="hint">Sigma export is best effort: {rule.sigma_warnings.join("; ")}.</p>
        )}
        {exported && (
          <pre className="json" aria-label={`${exported.format} export`}>
            {exported.text}
          </pre>
        )}
      </Card>

      {backtest ? (
        <Card title={`Backtest of version ${backtest.version}`} actions={<span className="small muted">{formatTime(backtest.created_at)}</span>}>
          <BacktestView result={backtest.result} />
        </Card>
      ) : (
        <Card title="Backtest">
          <EmptyState>Version {rule.current_version} has not been backtested yet; approval needs one.</EmptyState>
        </Card>
      )}

      {rule.versions.length > 1 && (
        <Card title="Versions">
          <table className="table compact">
            <tbody>
              {rule.versions.map((version) => (
                <tr key={version.version}>
                  <td className="mono">v{version.version}</td>
                  <td className="small">{version.rationale ?? "—"}</td>
                  <td className="small muted">
                    {version.created_by} · {formatTime(version.created_at)}
                  </td>
                  <td>
                    {version.version > 1 && (
                      <button
                        type="button"
                        className="link"
                        onClick={() =>
                          void run(async () =>
                            setDiff(
                              await api.get<RuleDiff>(`/rules/${rule.id}/diff`, {
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
            <div>
              <p className="small muted">
                v{diff.from_version} → v{diff.to_version}
              </p>
              {diff.changes.length === 0 ? (
                <p className="small">No differences.</p>
              ) : (
                diff.changes.map((change) => (
                  <div key={change.path} className="diff-row">
                    <span className="mono">{change.path}</span>
                    <span className="small">
                      {change.change === "changed" && (
                        <>
                          {JSON.stringify(change.old)} → {JSON.stringify(change.new)}
                        </>
                      )}
                      {change.change === "added" && <>added {JSON.stringify(change.new)}</>}
                      {change.change === "removed" && <>removed {JSON.stringify(change.old)}</>}
                    </span>
                  </div>
                ))
              )}
            </div>
          )}
        </Card>
      )}

      {dialog && (
        <ConfirmDialog
          title={dialog === "disable" ? `Disable ${rule.id}?` : `Retire ${rule.id}?`}
          description={
            dialog === "disable"
              ? "The rule stops firing on new events. Existing detections stay as they are."
              : "Retiring is final: the rule stops firing and cannot be edited again."
          }
          reasonLabel="Reason"
          confirmLabel={dialog === "disable" ? "Disable rule" : "Retire rule"}
          danger
          busy={busy}
          error={error}
          onCancel={() => setDialog(null)}
          onConfirm={({ reason }) => {
            setDialog(null);
            void run(() => api.post(`/rules/${rule.id}/${dialog}`, { reason }));
          }}
        />
      )}
    </div>
  );
}

export function DetectionEngineeringPage() {
  const { api, can } = useAuth();
  const [status, setStatus] = useState<string>("");
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const list = useApiQuery<{ items: RuleSummary[] }>("/rules/custom", { status: status || undefined });
  const detail = useApiQuery<RuleDetail>(selected ? `/rules/${selected}` : null);
  useLiveEvents(["rule"], () => {
    list.refetch();
    detail.refetch();
  });

  return (
    <section>
      <h1>Detection engineering</h1>
      <p className="muted">
        Custom rules are JSON, never code. Draft one here or from an incident, backtest it against stored events and
        the synthetic benign day, then have an approver approve and activate it. Editing an active rule creates a new
        version; the running version keeps detecting until you activate the new one.
      </p>
      <div className="rule-layout">
        <div>
          <Card
            title="Custom rules"
            actions={
              can("rules.draft") && (
                <button type="button" className="ghost" onClick={() => setCreating((open) => !open)}>
                  {creating ? "Close" : "New rule"}
                </button>
              )
            }
          >
            <div className="filters">
              <select aria-label="Rule status" value={status} onChange={(event) => setStatus(event.target.value)}>
                <option value="">All statuses</option>
                {STATUSES.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </div>
            <ErrorBanner error={list.error} />
            {list.loading && !list.data && <Loading />}
            {list.data && list.data.items.length === 0 && <EmptyState>No custom rules yet.</EmptyState>}
            <div className="rule-list">
              {list.data?.items.map((rule) => (
                <button
                  key={rule.id}
                  type="button"
                  className={rule.id === selected ? "rule-row selected" : "rule-row"}
                  onClick={() => setSelected(rule.id)}
                >
                  <span>
                    <span className="mono">{rule.id}</span> <StatusBadge status={rule.status} />
                  </span>
                  <span className="small">{rule.name}</span>
                  <span className="muted small">
                    v{rule.current_version}
                    {rule.active_version !== null && rule.active_version !== rule.current_version
                      ? ` · v${rule.active_version} running`
                      : ""}
                  </span>
                </button>
              ))}
            </div>
          </Card>
        </div>
        <div>
          {creating && (
            <Card title="New rule">
              <RuleEditor
                submitLabel="Create draft"
                onCancel={() => setCreating(false)}
                onSubmit={async (definition, rationale) => {
                  const created = await api.post<RuleSummary>("/rules", { definition, rationale });
                  setCreating(false);
                  setSelected(created.id);
                  list.refetch();
                }}
              />
            </Card>
          )}
          {selected && detail.loading && !detail.data && <Loading />}
          {selected && detail.error ? <ErrorBanner error={detail.error} /> : null}
          {detail.data && (
            <RuleDetailView
              rule={detail.data}
              onChanged={() => {
                detail.refetch();
                list.refetch();
              }}
            />
          )}
          {!selected && !creating && <EmptyState>Select a rule to see its definition, backtests and history.</EmptyState>}
        </div>
      </div>
    </section>
  );
}
