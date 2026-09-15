import { useState } from "react";
import { EmptyState, ErrorBanner, Loading } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import { ProposalCard } from "./ProposalCard";
import type { Proposal } from "./types";

export function ProposalsPage() {
  const [status, setStatus] = useState("PROPOSED");
  const { data, error, loading, refetch } = useApiQuery<{ items: Proposal[] }>("/agent/proposals", { status });
  useLiveEvents(["agent", "chat"], refetch);

  return (
    <section>
      <h1>Agent proposals</h1>
      <p className="muted">
        The agent drafts changes; it cannot make them. Applying a proposal runs the normal action under your identity and permission. Approvals,
        executions, rule activation, report finalisation and settings are never proposable.
      </p>
      <div className="filters">
        <select aria-label="Proposal status" value={status} onChange={(e) => setStatus(e.target.value)}>
          {["PROPOSED", "APPLIED", "DISMISSED", "STALE"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      <ErrorBanner error={error} />
      {loading && !data && <Loading />}
      {data && data.items.length === 0 && <EmptyState>No {status.toLowerCase()} proposals.</EmptyState>}
      <div className="scenario-grid">
        {data?.items.map((proposal) => (
          <ProposalCard key={proposal.id} proposal={proposal} onChanged={refetch} />
        ))}
      </div>
    </section>
  );
}
