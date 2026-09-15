import type { ComponentType } from "react";
import type { IncidentDetail } from "./types";

export interface IncidentTabProps {
  incident: IncidentDetail;
  /** Highlight these event IDs in the incident timeline. */
  onCite: (eventIds: string[]) => void;
}

export interface IncidentTab {
  featureId: string;
  id: string;
  label: string;
  /** Tabs with order < 50 appear right after Analysis; others after Responses. */
  order: number;
  Component: ComponentType<IncidentTabProps>;
}
