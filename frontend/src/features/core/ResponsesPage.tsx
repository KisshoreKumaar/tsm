import { useState } from "react";
import type { Page } from "../../core/types";
import { Card, ErrorBanner, Loading, Pagination } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import { ResponsesPanel } from "./ResponsesPanel";
import type { PlaybookInfo, ResponseRecord } from "./types";

const LIMIT = 25;

export function ResponsesPage() {
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const { data, error, loading, refetch } = useApiQuery<Page<ResponseRecord>>("/responses", { status, offset, limit: LIMIT });
  const { data: playbooks } = useApiQuery<PlaybookInfo>("/playbooks");
  const { data: endpoints, refetch: refetchEndpoints } = useApiQuery<{ items: { asset: string; state: string; updated_at: string; updated_by: string }[] }>(
    "/endpoints",
  );
  useLiveEvents(["response"], () => {
    refetch();
    refetchEndpoints();
  });

  return (
    <section>
      <h1>Responses</h1>
      <p className="muted">
        All actions are simulated against a virtual endpoint registry. Approval requires typing the confirmation phrase, is bound to
        the incident revision and expires after 15 minutes{playbooks?.two_person ? "; the two-person rule is enabled" : ""}.
      </p>
      <div className="filters">
        <select aria-label="Status" value={status} onChange={(e) => (setOffset(0), setStatus(e.target.value))}>
          <option value="">All statuses</option>
          {["PENDING", "APPROVED", "EXECUTED", "REJECTED", "CANCELLED", "EXPIRED"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      <ErrorBanner error={error} />
      {loading && !data && <Loading />}
      {data && (
        <Card>
          <ResponsesPanel responses={data.items} phrase={playbooks?.confirmation_phrase ?? "APPROVE SIMULATION"} onChanged={refetch} showIncident />
          <Pagination offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
        </Card>
      )}
      <Card title="Virtual endpoint registry">
        {endpoints && endpoints.items.length > 0 ? (
          <table className="table compact">
            <tbody>
              {endpoints.items.map((endpoint) => (
                <tr key={endpoint.asset}>
                  <td className="mono">{endpoint.asset}</td>
                  <td>{endpoint.state}</td>
                  <td className="muted small">by {endpoint.updated_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted">No simulated endpoint changes yet.</p>
        )}
      </Card>
    </section>
  );
}
