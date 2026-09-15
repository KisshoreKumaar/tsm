import { useState } from "react";
import { useAuth } from "../../core/auth";
import { errorMessage, formatTime } from "../../core/format";
import type { Page } from "../../core/types";
import { Card, ErrorBanner, JsonBlock, Loading, Pagination } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";

interface AuditRecord {
  seq: number;
  ts: string;
  action: string;
  actor: string;
  subject_type: string | null;
  subject_id: string | null;
  body: Record<string, unknown>;
  digest: string;
}

const LIMIT = 50;

export function AuditPage() {
  const { api, can } = useAuth();
  const [action, setAction] = useState("");
  const [filter, setFilter] = useState("");
  const [offset, setOffset] = useState(0);
  const { data, error, loading } = useApiQuery<Page<AuditRecord>>("/audit", { action: filter, offset, limit: LIMIT });
  const [verification, setVerification] = useState<unknown>(null);
  const [checkpoint, setCheckpoint] = useState<unknown>(null);
  const [opError, setOpError] = useState<string | null>(null);

  async function verify() {
    setOpError(null);
    try {
      setVerification(await api.get("/audit/verify"));
    } catch (err) {
      setOpError(errorMessage(err));
    }
  }

  async function exportCheckpoint() {
    setOpError(null);
    try {
      const head = await api.get<Record<string, unknown>>("/audit/checkpoint");
      setCheckpoint(head);
      const blob = new Blob([JSON.stringify(head, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `aegis-audit-checkpoint-${String(head.head_seq)}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setOpError(errorMessage(err));
    }
  }

  return (
    <section>
      <h1>Audit trail</h1>
      <p className="muted">Every state change is recorded in the same transaction and chained with HMAC-SHA256.</p>
      <div className="form-row">
        <button type="button" onClick={verify}>
          Verify chain
        </button>
        {can("audit.export") && (
          <button type="button" className="ghost" onClick={exportCheckpoint}>
            Export checkpoint
          </button>
        )}
      </div>
      {opError && (
        <p role="alert" className="error">
          {opError}
        </p>
      )}
      {verification !== null && (
        <Card title="Verification result">
          <JsonBlock value={verification} />
        </Card>
      )}
      {checkpoint !== null && (
        <Card title="Checkpoint (store outside this system)">
          <JsonBlock value={checkpoint} />
        </Card>
      )}
      <form
        className="filters"
        onSubmit={(event) => {
          event.preventDefault();
          setOffset(0);
          setFilter(action.trim());
        }}
      >
        <input aria-label="Action filter" placeholder="Action, e.g. response.executed" value={action} onChange={(e) => setAction(e.target.value)} />
        <button type="submit">Filter</button>
      </form>
      <ErrorBanner error={error} />
      {loading && !data && <Loading />}
      {data && (
        <table className="table">
          <thead>
            <tr>
              <th>#</th>
              <th>Time</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Subject</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((record) => (
              <tr key={record.seq}>
                <td className="mono small">{record.seq}</td>
                <td className="small nowrap">{formatTime(record.ts)}</td>
                <td className="mono small">{record.action}</td>
                <td className="small">{record.actor}</td>
                <td className="mono small">{record.subject_type ? `${record.subject_type}:${record.subject_id?.slice(0, 8)}` : "—"}</td>
                <td>
                  <details>
                    <summary className="small">view</summary>
                    <JsonBlock value={record.body} />
                    <div className="mono small muted">digest {record.digest.slice(0, 16)}…</div>
                  </details>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && <Pagination offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />}
    </section>
  );
}
