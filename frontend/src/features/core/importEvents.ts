export const MAX_IMPORT_EVENTS = 500;
export const MAX_IMPORT_BYTES = 4 * 1024 * 1024;

/** Accepts a JSON array, a {"events": [...]} object, a single event object, or JSON Lines. */
export function parseEventImport(text: string): Record<string, unknown>[] {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("Paste or upload at least one event.");
  }
  if (new Blob([trimmed]).size > MAX_IMPORT_BYTES) {
    throw new Error("The import is larger than 4 MiB.");
  }
  let events: unknown[];
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        events = parsed;
      } else if (parsed && typeof parsed === "object" && Array.isArray((parsed as { events?: unknown }).events)) {
        events = (parsed as { events: unknown[] }).events;
      } else {
        events = [parsed];
      }
    } catch {
      events = parseLines(trimmed);
    }
  } else {
    events = parseLines(trimmed);
  }
  if (events.length === 0) {
    throw new Error("No events found.");
  }
  if (events.length > MAX_IMPORT_EVENTS) {
    throw new Error(`At most ${MAX_IMPORT_EVENTS} events can be imported at once.`);
  }
  events.forEach((event, index) => {
    if (!event || typeof event !== "object" || Array.isArray(event)) {
      throw new Error(`Item ${index + 1} is not a JSON object.`);
    }
  });
  return events as Record<string, unknown>[];
}

function parseLines(text: string): unknown[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line) as unknown;
      } catch {
        throw new Error(`Line ${index + 1} is not valid JSON.`);
      }
    });
}
