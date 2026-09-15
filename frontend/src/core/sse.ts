/**
 * Server-Sent Events over fetch, so the bearer token travels in the Authorization header
 * (the native EventSource API cannot send headers and would force tokens into URLs).
 */

export interface SseMessage {
  id: string | null;
  event: string;
  data: unknown;
}

export function parseSseBuffer(buffer: string): { messages: SseMessage[]; rest: string } {
  const blocks = buffer.replace(/\r\n/g, "\n").split("\n\n");
  const rest = blocks.pop() ?? "";
  const messages: SseMessage[] = [];
  for (const block of blocks) {
    let event = "message";
    let id: string | null = null;
    const dataLines: string[] = [];
    for (const line of block.split("\n")) {
      if (!line || line.startsWith(":")) {
        continue;
      }
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      let value = colon === -1 ? "" : line.slice(colon + 1);
      if (value.startsWith(" ")) {
        value = value.slice(1);
      }
      if (field === "event") {
        event = value;
      } else if (field === "data") {
        dataLines.push(value);
      } else if (field === "id") {
        id = value;
      }
    }
    if (dataLines.length === 0) {
      continue;
    }
    const raw = dataLines.join("\n");
    let data: unknown = raw;
    try {
      data = JSON.parse(raw);
    } catch {
      // Keep non-JSON payloads as text.
    }
    messages.push({ id, event, data });
  }
  return { messages, rest };
}

export async function readSse(
  body: ReadableStream<Uint8Array>,
  onMessage: (message: SseMessage) => void,
  signal?: AbortSignal,
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      if (signal?.aborted) {
        return;
      }
      const { value, done } = await reader.read();
      if (done) {
        return;
      }
      buffer += decoder.decode(value, { stream: true });
      const parsed = parseSseBuffer(buffer);
      buffer = parsed.rest;
      parsed.messages.forEach(onMessage);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // A pending read may keep the lock; the abort signal closes the stream.
    }
  }
}

export type StreamStatus = "connecting" | "open" | "closed" | "unauthorized";

export interface SubscribeOptions {
  url: string;
  getToken: () => string | null;
  onMessage: (message: SseMessage) => void;
  onStatus?: (status: StreamStatus) => void;
  fetchImpl?: typeof fetch;
  maxBackoffMs?: number;
}

/** Opens a resilient stream; returns an unsubscribe function. */
export function subscribe(options: SubscribeOptions): () => void {
  const controller = new AbortController();
  const fetchImpl: typeof fetch = options.fetchImpl ?? ((input, init) => fetch(input, init));
  let attempt = 0;

  const sleep = (ms: number) =>
    new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, ms);
      controller.signal.addEventListener(
        "abort",
        () => {
          clearTimeout(timer);
          resolve();
        },
        { once: true },
      );
    });

  const run = async () => {
    while (!controller.signal.aborted) {
      const token = options.getToken();
      if (!token) {
        options.onStatus?.("unauthorized");
        return;
      }
      options.onStatus?.("connecting");
      try {
        const response = await fetchImpl(options.url, {
          headers: { Authorization: `Bearer ${token}`, Accept: "text/event-stream" },
          signal: controller.signal,
          cache: "no-store",
          credentials: "omit",
        });
        if (response.status === 401 || response.status === 403) {
          options.onStatus?.("unauthorized");
          return;
        }
        if (!response.ok || !response.body) {
          throw new Error(`Stream failed with status ${response.status}`);
        }
        attempt = 0;
        options.onStatus?.("open");
        await readSse(response.body, options.onMessage, controller.signal);
      } catch {
        if (controller.signal.aborted) {
          return;
        }
      }
      options.onStatus?.("closed");
      attempt += 1;
      await sleep(Math.min(options.maxBackoffMs ?? 15_000, 500 * 2 ** Math.min(attempt, 5)));
    }
  };

  void run();
  return () => controller.abort();
}
