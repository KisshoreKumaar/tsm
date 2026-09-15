import { useCallback, useMemo, useState, type FormEvent } from "react";
import { useAuth } from "../../core/auth";
import { errorMessage } from "../../core/format";
import { Card, ErrorBanner } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import type { IncidentTabProps } from "../core/incidentTabTypes";
import { ChatThread } from "./ChatThread";
import type { ChatRecord, PostMessageResult } from "./types";

export function AnalystTab({ incident, onCite }: IncidentTabProps) {
  const { api, can } = useAuth();
  const { data: chats, refetch: refetchChats } = useApiQuery<{ items: ChatRecord[]; quick_prompts: Record<string, string> }>("/chats", {
    subject_type: "incident",
    subject_id: incident.id,
  });
  const chatId = chats?.items[0]?.id ?? null;
  const { data: chat, refetch } = useApiQuery<ChatRecord>(chatId ? `/chats/${chatId}` : null);
  const [question, setQuestion] = useState("");
  const [mode, setMode] = useState<"quick" | "deep">("quick");
  const [error, setError] = useState<string | null>(null);
  const [eta, setEta] = useState<number | null>(null);
  const refs = useMemo(() => new Map(incident.events.map((event, index) => [event.id, `E${index + 1}`])), [incident.events]);
  const refFor = useCallback((eventId: string) => refs.get(eventId) ?? eventId.slice(0, 6), [refs]);

  useLiveEvents(["chat"], (message) => {
    const data = message.data as { chat_id?: string } | null;
    if (data?.chat_id && data.chat_id === chatId) refetch();
  });

  async function ask(text: string) {
    const content = text.trim();
    if (!content) return;
    setError(null);
    try {
      let id = chatId;
      if (!id) {
        id = (await api.post<ChatRecord>("/chats", { subject_type: "incident", subject_id: incident.id })).id;
        refetchChats();
      }
      const posted = await api.post<PostMessageResult>(`/chats/${id}/messages`, { content, mode });
      setEta(posted.eta_seconds);
      setQuestion("");
      if (id === chatId) refetch();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  const prompts = chats?.quick_prompts ?? {};
  return (
    <Card title="AI analyst">
      <p className="hint">
        Answers use only this incident&apos;s evidence. Facts cite events; the analyst cannot change anything. On the self-hosted model an answer can take
        about a minute.
      </p>
      {can("ai.use") ? (
        <>
          <div className="chips">
            {Object.entries(prompts).map(([key, prompt]) => (
              <button key={key} type="button" className="ghost" onClick={() => void ask(prompt)}>
                {prompt}
              </button>
            ))}
          </div>
          <form
            className="inline-form"
            onSubmit={(event: FormEvent<HTMLFormElement>) => {
              event.preventDefault();
              void ask(question);
            }}
          >
            <input aria-label="Question" placeholder="Ask about this incident" maxLength={1000} value={question} onChange={(e) => setQuestion(e.target.value)} />
            <select aria-label="Mode" value={mode} onChange={(e) => setMode(e.target.value as "quick" | "deep")}>
              <option value="quick">Quick (one call)</option>
              <option value="deep">Deep (read-only tools)</option>
            </select>
            <button type="submit" disabled={!question.trim()}>
              Ask
            </button>
          </form>
        </>
      ) : (
        <p className="muted">Your role cannot use the AI analyst.</p>
      )}
      <ErrorBanner error={error ? new Error(error) : null} />
      {chat?.messages && chat.messages.length > 0 ? (
        <ChatThread messages={chat.messages} refFor={refFor} onCite={onCite} onAsk={can("ai.use") ? (q) => void ask(q) : undefined} eta={eta} notes />
      ) : (
        <p className="muted">No questions yet.</p>
      )}
    </Card>
  );
}
