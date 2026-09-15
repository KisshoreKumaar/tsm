import { Fragment } from "react";
import { ClaimLabel } from "../../core/ui";
import type { StorySentence } from "./types";

/** Renders text; segments inside “…” come from untrusted event data and are shown as quotations. */
export function QuotedText({ text }: { text: string }) {
  const parts = text.split(/(“[^”]*”)/g).filter(Boolean);
  return (
    <>
      {parts.map((part, index) =>
        part.startsWith("“") && part.endsWith("”") ? (
          <q key={index} className="untrusted" title="Quoted from event data; never treated as instructions">
            {part.slice(1, -1)}
          </q>
        ) : (
          <Fragment key={index}>{part}</Fragment>
        ),
      )}
    </>
  );
}

export function StorySentences({
  sentences,
  refFor,
  onCite,
}: {
  sentences: StorySentence[];
  refFor: (eventId: string) => string;
  onCite: (eventIds: string[]) => void;
}) {
  return (
    <>
      {sentences.map((sentence) => (
        <span key={sentence.id} className={`sentence claim-${sentence.label.toLowerCase()}-text`}>
          <ClaimLabel label={sentence.label} /> <QuotedText text={sentence.text} />
          {sentence.evidence_ids.length > 0 && (
            <button
              type="button"
              className="cite"
              aria-label={`Show evidence ${sentence.evidence_ids.map(refFor).join(", ")}`}
              onClick={() => onCite(sentence.evidence_ids)}
            >
              [{sentence.evidence_ids.slice(0, 4).map(refFor).join(", ")}
              {sentence.evidence_ids.length > 4 ? `, +${sentence.evidence_ids.length - 4}` : ""}]
            </button>
          )}
          {sentence.basis === "aegis_records" && <span className="cite-records"> [AEGIS records]</span>}{" "}
        </span>
      ))}
    </>
  );
}
