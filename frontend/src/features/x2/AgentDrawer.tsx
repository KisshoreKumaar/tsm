import { useCallback, useMemo, useState, type FormEvent } from "react";
import { matchPath, useLocation } from "react-router-dom";
import { useAuth } from "../../core/auth";
import { errorMessage } from "../../core/format";
import { ErrorBanner } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import { ChatThread } from "../f3/ChatThread";
import type { ChatRecord, PostMessageResult } from "../f3/types";
import { ProposalCard } from "./ProposalCard";
import type { Proposal } from "./types";
import "../ai.css";

interface Subject {
  key: string;
  subject_type: "incident" | "campaign" | "global";
  subject_id: string | null;
  label: string;
}

function subjectFor(pathname: string): Subject {
  const incident = matchPath("/incidents/:id", pathname);
  if (incident?.params.id) {
    return { key: `incident:${incident.params.id}`, subject_type: "incident", subject_id: incident.params.id, label: "this incident" };
  }
  const campaign = matchPath("/campaigns/:id", pathname);
  if (campaign?.params.id) {
    return { key: `campaign:${campaign.params.id}`, subject_type: "campaign", subject_id: campaign.params.id, label: "this campaign" };
  }
  return { key: "global", subject_type: "global", subject_id: null, label: "the whole workspace" };
}

export function AgentDrawer({ onClose }: { onClose: () => void }) {
  const { api } = useAuth();
  const location = useLocation();
  const subject = useMemo(() => subjectFor(location.pathname), [location.pathname]);
  const [chats, setChats] = useState<Record<string, string>>({});
  const chatId = chats[subject.key] ?? null;
  const { data: chat, refetch } = useApiQuery<ChatRecord>(chatId ? `/chats/${chatId}` : null);
  const { data: proposals, refetch: refetchProposals } = useApiQuery<{ items: Proposal[] }>(chatId ? "/agent/proposals" : null, {
    chat_id: chatId ?? undefined,
  });
  const [question, setQuestion] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [eta, setEta] = useState<number | null>(null);
  const refFor = useCallback((eventId: string) => eventId.slice(0, 6), []);

  useLiveEvents(["chat", "agent"], (message) => {
    const data = message.data as { chat_id?: string } | null;
    if (message.event.startsWith("agent") || (data?.chat_id && data.chat_id === chatId)) {
      refetch();
      refetchProposals();
    }
  });

  async function ask(text: string) {
    const content = text.trim();
    if (!content) return;
    setError(null);
    try {
      let id = chatId;
      if (!id) {
        const created = await api.post<ChatRecord>("/chats", { subject_type: subject.subject_type, subject_id: subject.subject_id });
        id = created.id;
        setChats((current) => ({ ...current, [subject.key]: created.id }));
      }
      const posted = await api.post<PostMessageResult>(`/chats/${id}/messages`, { content, mode: "agent" });
      setEta(posted.eta_seconds);
      setQuestion("");
      if (id === chatId) refetch();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <aside className="drawer" aria-label="Agent console">
      <div className="drawer-header">
        <strong>Agent · {subject.label}</strong>
        <button type="button" className="ghost" onClick={onClose}>
          Close
        </button>
      </div>
      <div className="drawer-body">
        <p className="hint">
          The agent reads across AEGIS with read-only tools and can draft proposals. It never changes anything; you review and apply proposals under your
          own permissions.
        </p>
        <form
          className="form"
          onSubmit={(event: FormEvent<HTMLFormElement>) => {
            event.preventDefault();
            void ask(question);
          }}
        >
          <textarea aria-label="Ask the agent" rows={3} maxLength={1000} value={question} onChange={(e) => setQuestion(e.target.value)} />
          <div className="form-row">
            <button type="submit" disabled={!question.trim()}>
              Ask the agent
            </button>
            <button type="button" className="ghost" onClick={() => void ask("What needs my attention first, and why?")}>
              What needs attention?
            </button>
          </div>
        </form>
        <ErrorBanner error={error ? new Error(error) : null} />
        {proposals && proposals.items.length > 0 && (
          <>
            <strong>Proposals from this conversation</strong>
            {proposals.items.map((proposal) => (
              <ProposalCard key={proposal.id} proposal={proposal} onChanged={refetchProposals} />
            ))}
          </>
        )}
        {chat?.messages && <ChatThread messages={[...chat.messages].reverse()} refFor={refFor} onCite={() => {}} onAsk={(q) => void ask(q)} eta={eta} notes={false} />}
      </div>
    </aside>
  );
}
