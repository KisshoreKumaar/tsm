import { useState, type ReactNode } from "react";
import { useAuth } from "../../core/auth";
import { errorMessage, formatTime } from "../../core/format";
import { Card } from "../../core/ui";
import { StorySentences } from "./StorySentences";
import type { StoryResponse } from "./types";
import "./story.css";

export function StoryView({
  data,
  onCite,
  exportPath,
  actions,
}: {
  data: StoryResponse;
  onCite: (eventIds: string[]) => void;
  exportPath: string;
  actions?: ReactNode;
}) {
  const { api } = useAuth();
  const [format, setFormat] = useState<"executive" | "analyst">("executive");
  const [exportError, setExportError] = useState<string | null>(null);
  const { story } = data;
  const refs = new Map(story.evidence_index.map((item) => [item.event_id, item.ref]));
  const refFor = (eventId: string) => refs.get(eventId) ?? eventId.slice(0, 6);

  async function exportMarkdown() {
    setExportError(null);
    try {
      const text = await api.text(exportPath, { format: "full" });
      const url = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `aegis-${story.subject_type}-${story.subject_id.slice(0, 8)}-story.md`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setExportError(errorMessage(err));
    }
  }

  return (
    <Card>
      <div className="story-toolbar">
        <div className="segmented" role="group" aria-label="Story format">
          <button type="button" aria-pressed={format === "executive"} onClick={() => setFormat("executive")}>
            Executive
          </button>
          <button type="button" aria-pressed={format === "analyst"} onClick={() => setFormat("analyst")}>
            Analyst
          </button>
        </div>
        <span className={story.source === "ai_polished" ? "badge ai" : "badge"}>{story.badge}</span>
        {!story.citations_valid && <span className="badge warn">Citation check failed</span>}
        {data.stale && <span className="badge stale">Saved version is stale (incident changed)</span>}
        <span className="muted small">
          revision {story.subject_revision} · generated {formatTime(story.generated_at)}
        </span>
        <button type="button" className="ghost" onClick={exportMarkdown}>
          Export Markdown
        </button>
        {actions}
      </div>
      {exportError && (
        <p role="alert" className="error">
          {exportError}
        </p>
      )}
      {format === "executive" ? (
        <dl className="story-executive">
          {story.executive.lines.map((line) => (
            <div key={line.key}>
              <dt>{line.heading}</dt>
              <dd>
                <StorySentences sentences={[line.sentence]} refFor={refFor} onCite={onCite} />
              </dd>
            </div>
          ))}
        </dl>
      ) : (
        <>
          {story.analyst.paragraphs.map((paragraph, index) => (
            <p key={index} className="story-paragraph">
              <StorySentences sentences={paragraph} refFor={refFor} onCite={onCite} />
            </p>
          ))}
          <p className="hint">{story.analyst.word_count} words. Click a citation to highlight its events in the timeline.</p>
        </>
      )}
      <p className="hint">Labels: FACT (reported evidence), INFERENCE (what a rule suggests), HYPOTHESIS (possible explanation), UNKNOWN (missing context).</p>
    </Card>
  );
}
