import { useState } from "react";
import { useAuth } from "../../core/auth";
import { errorMessage } from "../../core/format";
import { StorySentences } from "../f2/StorySentences";
import type { StorySentence } from "../f2/types";
import type { AnalystAnswer } from "./types";

export function answerSentences(answer: AnalystAnswer): StorySentence[] {
  return answer.claims.map((claim, index) => ({
    id: `c${index}`,
    label: claim.label,
    text: claim.downgraded ? `${claim.text} (citation rejected, so not shown as fact)` : claim.text,
    evidence_ids: claim.evidence_ids,
    basis: "events",
    refs: [],
  }));
}

export function AnswerView({
  answer,
  refFor,
  onCite,
  onAsk,
  notesTarget,
}: {
  answer: AnalystAnswer;
  refFor: (eventId: string) => string;
  onCite: (eventIds: string[]) => void;
  onAsk?: (question: string) => void;
  notesTarget?: { chatId: string; messageId: string };
}) {
  const { api, can } = useAuth();
  const [noteText, setNoteText] = useState<string | null>(null);
  const [noteState, setNoteState] = useState<string | null>(null);

  async function addNote() {
    if (!notesTarget || noteText === null) return;
    try {
      await api.post(`/chats/${notesTarget.chatId}/messages/${notesTarget.messageId}/add-to-notes`, { text: noteText });
      setNoteState("Added to incident notes as your note (referencing this AI answer).");
      setNoteText(null);
    } catch (err) {
      setNoteState(errorMessage(err));
    }
  }

  return (
    <div className="chat-answer">
      <div className="header-badges">
        <span className={answer.used_ai ? "badge ai" : "badge"}>{answer.used_ai ? `AI (${answer.ai_status})` : "Deterministic"}</span>
        {answer.model && answer.used_ai && <span className="badge">{answer.model}</span>}
        <span className="badge">confidence: {answer.confidence}</span>
        {answer.grounding && answer.grounding.claims > 0 && (
          <span className="badge">
            {answer.grounding.grounded}/{answer.grounding.claims} claims cited
          </span>
        )}
        {answer.steps !== undefined && answer.steps > 0 && <span className="badge">{answer.steps} tool step(s)</span>}
      </div>
      {answer.injection_suspected && (
        <div className="warning-banner small">Instruction-like text was found in the evidence. It was treated as data and never followed.</div>
      )}
      {answer.error && !answer.used_ai && <p className="hint">{answer.error}</p>}
      <p>{answer.summary}</p>
      <p>
        <StorySentences sentences={answerSentences(answer)} refFor={refFor} onCite={onCite} />
      </p>
      {answer.suggested_actions.length > 0 && (
        <>
          <div className="small muted">Suggested investigation steps (you decide; nothing runs automatically)</div>
          <ul className="small">
            {answer.suggested_actions.map((action) => (
              <li key={action.text}>
                {action.text}
                {action.playbook && <span className="muted"> · simulated playbook available: {action.playbook}</span>}
              </li>
            ))}
          </ul>
        </>
      )}
      {answer.actions_removed ? <p className="hint">{answer.actions_removed} unsafe suggestion(s) were removed by guardrails.</p> : null}
      {onAsk && answer.suggested_next_questions.length > 0 && (
        <div className="chips">
          {answer.suggested_next_questions.map((question) => (
            <button key={question} type="button" className="ghost" onClick={() => onAsk(question)}>
              {question}
            </button>
          ))}
        </div>
      )}
      {notesTarget && can("investigate") && (
        <div>
          {noteText === null ? (
            <button type="button" className="link" onClick={() => setNoteText(answer.summary)}>
              Add to notes
            </button>
          ) : (
            <div className="form">
              <textarea aria-label="Note text" rows={3} value={noteText} onChange={(e) => setNoteText(e.target.value)} />
              <div className="form-row">
                <button type="button" onClick={addNote} disabled={!noteText.trim()}>
                  Save as my note
                </button>
                <button type="button" className="ghost" onClick={() => setNoteText(null)}>
                  Cancel
                </button>
              </div>
            </div>
          )}
          {noteState && <p className="hint">{noteState}</p>}
        </div>
      )}
    </div>
  );
}
