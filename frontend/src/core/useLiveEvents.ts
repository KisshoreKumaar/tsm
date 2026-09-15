import { useEffect, useRef, useState } from "react";
import { useAuth } from "./auth";
import { subscribe, type SseMessage, type StreamStatus } from "./sse";

/** Subscribe to live updates for the given topic prefixes (e.g. ["incident", "prediction"]). */
export function useLiveEvents(topics: string[], onMessage: (message: SseMessage) => void): StreamStatus {
  const { getToken } = useAuth();
  const handler = useRef(onMessage);
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const key = topics.join(",");

  useEffect(() => {
    handler.current = onMessage;
  }, [onMessage]);

  useEffect(
    () =>
      subscribe({
        url: `/api/stream?topics=${encodeURIComponent(key)}`,
        getToken,
        onMessage: (message) => handler.current(message),
        onStatus: setStatus,
      }),
    [key, getToken],
  );

  return status;
}
