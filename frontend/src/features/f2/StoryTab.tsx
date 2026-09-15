import { useEffect, useState } from "react";
import { useAuth } from "../../core/auth";
import { errorMessage } from "../../core/format";
import { ErrorBanner, Loading } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import type { IncidentTabProps } from "../core/incidentTabTypes";
import { StoryView } from "./StoryView";
import type { StoryResponse } from "./types";

export function StoryTab({ incident, onCite }: IncidentTabProps) {
  const { api, can } = useAuth();
  const { data, error, loading, refetch } = useApiQuery<StoryResponse>(`/incidents/${incident.id}/story`);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    refetch();
  }, [incident.revision, refetch]);

  async function regenerate() {
    setBusy(true);
    setActionError(null);
    try {
      await api.post(`/incidents/${incident.id}/story/regenerate`, {});
      refetch();
    } catch (err) {
      setActionError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBanner error={error} />;
  return (
    <>
      {actionError && (
        <p role="alert" className="error">
          {actionError}
        </p>
      )}
      <StoryView
        data={data}
        onCite={onCite}
        exportPath={`/incidents/${incident.id}/story.md`}
        actions={
          can("ai.use") && (
            <button type="button" className="ghost" onClick={regenerate} disabled={busy}>
              {busy ? "Saving…" : data.saved ? `Regenerate (saved v${data.saved.version})` : "Save version"}
            </button>
          )
        }
      />
    </>
  );
}
