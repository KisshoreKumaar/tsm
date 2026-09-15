import { useEffect } from "react";
import { Link } from "react-router-dom";
import { useApiQuery } from "../../core/useApiQuery";
import type { AiStatus } from "./types";
import "../ai.css";

export function AiStatusChip() {
  const { data, refetch } = useApiQuery<AiStatus>("/ai/status");
  useEffect(() => {
    const timer = window.setInterval(refetch, 30_000);
    return () => window.clearInterval(timer);
  }, [refetch]);
  if (!data) return null;
  return (
    <Link to="/ai/status" className="ai-chip" title="AI status">
      <span className={data.enabled ? "dot on" : "dot"} />
      {data.enabled ? `AI: ${data.active_provider?.model ?? "enabled"}` : "AI: deterministic mode"}
      {data.queue.queued + data.queue.running > 0 && ` · ${data.queue.queued + data.queue.running} in queue`}
    </Link>
  );
}
