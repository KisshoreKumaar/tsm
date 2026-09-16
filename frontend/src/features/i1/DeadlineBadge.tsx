import type { DeadlineInfo } from "./types";
import "./compliance.css";

export function remainingText(seconds: number): string {
  if (seconds <= 0) return "overdue";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours >= 24) return `${Math.floor(hours / 24)} d ${hours % 24} h left`;
  if (hours > 0) return `${hours} h ${minutes} m left`;
  return `${minutes} m left`;
}

export function DeadlineBadge({ deadline, timezone = "UTC" }: { deadline: DeadlineInfo; timezone?: "UTC" | "IST" }) {
  const stamp = timezone === "IST" ? deadline.deadline_ist : deadline.deadline_utc;
  return (
    <span className={`deadline deadline-${deadline.state}`} title={deadline.label}>
      {deadline.overdue ? "Reporting deadline passed" : remainingText(deadline.seconds_remaining)}
      <span className="muted small"> · {stamp.replace("T", " ")} {timezone}</span>
    </span>
  );
}
