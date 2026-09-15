import { useJobStream } from "../../core/useJobStream";
import { AnswerView } from "./AnswerView";
import type { AnalystAnswer, ChatMessageRecord } from "./types";
import "../ai.css";

function Pending({ message, eta }: { message: ChatMessageRecord; eta: number | null }) {
  const stream = useJobStream(message.job_id);
  return (
    <div className="chat-answer">
      <p className="muted small">
        {stream.status === "RUNNING" || stream.text || stream.steps.length ? "Thinking…" : "Queued…"}
        {eta !== null && !stream.text && ` (estimated ${eta}s on the current model)`}
      </p>
      {stream.steps.length > 0 && (
        <ul className="small muted">
          {stream.steps.map((step) => (
            <li key={step.step}>
              Step {step.step}: {step.tool} {step.ok ? "" : "(error)"}
            </li>
          ))}
        </ul>
      )}
      {stream.text && <div className="streaming">{stream.text}</div>}
    </div>
  );
}

export function ChatThread({
  messages,
  refFor,
  onCite,
  onAsk,
  eta,
  notes,
}: {
  messages: ChatMessageRecord[];
  refFor: (eventId: string) => string;
  onCite: (eventIds: string[]) => void;
  onAsk?: (question: string) => void;
  eta: number | null;
  notes: boolean;
}) {
  return (
    <div className="chat">
      {messages.map((message) => {
        if (message.role === "user") {
          return (
            <div key={message.id} className="chat-question">
              {String(message.content.text ?? "")}
              <div className="small muted">
                {message.actor} · {message.mode}
              </div>
            </div>
          );
        }
        if (message.status === "pending") {
          return <Pending key={message.id} message={message} eta={eta} />;
        }
        if (message.status === "failed") {
          return (
            <div key={message.id} className="chat-answer failed">
              {String(message.content.error ?? "The answer failed.")}
            </div>
          );
        }
        return (
          <AnswerView
            key={message.id}
            answer={message.content as unknown as AnalystAnswer}
            refFor={refFor}
            onCite={onCite}
            onAsk={onAsk}
            notesTarget={notes ? { chatId: message.chat_id, messageId: message.id } : undefined}
          />
        );
      })}
    </div>
  );
}
