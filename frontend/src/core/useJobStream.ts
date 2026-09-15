import { useEffect, useState } from "react";
import { useAuth } from "./auth";
import { subscribe } from "./sse";

export interface JobStep {
  step: number;
  tool: string;
  ok: boolean;
}

/** Streams one job's progress: tokens from the model, tool steps and status changes. */
export function useJobStream(jobId: string | null): { text: string; steps: JobStep[]; status: string | null } {
  const { getToken } = useAuth();
  const [text, setText] = useState("");
  const [steps, setSteps] = useState<JobStep[]>([]);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    setText("");
    setSteps([]);
    setStatus(null);
    if (!jobId) {
      return;
    }
    return subscribe({
      url: `/api/jobs/${jobId}/stream`,
      getToken,
      onMessage: (message) => {
        const data = (message.data ?? {}) as Record<string, unknown>;
        if (message.event === "job.progress") {
          if (typeof data.token === "string") {
            const token = data.token;
            setText((current) => (current + token).slice(-4000));
          }
          if (typeof data.tool === "string") {
            const tool = data.tool;
            setSteps((current) => [...current, { step: Number(data.step), tool, ok: Boolean(data.ok) }]);
          }
        } else if (message.event === "job.updated" && typeof data.status === "string") {
          setStatus(data.status);
        }
      },
    });
  }, [jobId, getToken]);

  return { text, steps, status };
}
