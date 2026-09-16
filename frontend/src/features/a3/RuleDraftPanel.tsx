import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../core/auth";
import { errorMessage } from "../../core/format";
import { Card } from "../../core/ui";
import type { IncidentTabProps } from "../core/incidentTabTypes";

interface JobView {
  status: string;
  result: { rule_id?: string; source?: string } | null;
  error: string | null;
}

export function RuleDraftPanel({ incident }: IncidentTabProps) {
  const { api, can } = useAuth();
  const [jobId, setJobId] = useState<string | null>(null);
  const [drafted, setDrafted] = useState<{ ruleId: string; source: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    const timer = window.setInterval(async () => {
      try {
        const job = await api.get<JobView>(`/jobs/${jobId}`);
        if (cancelled) return;
        if (job.status === "SUCCEEDED" && job.result?.rule_id) {
          setDrafted({ ruleId: job.result.rule_id, source: job.result.source ?? "draft" });
          setJobId(null);
        } else if (job.status === "FAILED" || job.status === "CANCELLED") {
          setError(job.error ?? "The draft did not finish");
          setJobId(null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(errorMessage(err));
          setJobId(null);
        }
      }
    }, 1500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [jobId, api]);

  async function draft() {
    setError(null);
    setDrafted(null);
    try {
      const response = await api.post<{ job_id: string }>(`/rules/draft-from-incident/${incident.id}`, {});
      setJobId(response.job_id);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <Card title="Draft a detection rule from this incident">
      <p className="hint">
        AEGIS generalises this incident&apos;s strongest detection into a JSON rule: the dominant event kind, shared
        behaviour and a threshold, never a one-off address. The draft is never active; backtest it and have it
        approved on the detection engineering page.
      </p>
      {can("rules.draft") ? (
        <div className="form-row">
          <button type="button" onClick={draft} disabled={jobId !== null}>
            {jobId ? "Drafting…" : "Draft rule from this incident"}
          </button>
          {jobId && <span className="small muted">With an LLM enabled this can take about a minute.</span>}
        </div>
      ) : (
        <p className="muted">Your role cannot draft detection rules.</p>
      )}
      {drafted && (
        <p className="small">
          Created <span className="mono">{drafted.ruleId}</span> as a {drafted.source === "ai_draft" ? "AI" : "deterministic"} draft.{" "}
          <Link to="/detection-engineering">Open detection engineering</Link> to backtest and approve it.
        </p>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </Card>
  );
}
