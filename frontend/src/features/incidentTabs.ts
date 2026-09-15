import type { FeatureManifestEntry } from "../core/types";
import type { IncidentTab } from "./core/incidentTabTypes";
import { RelatedPanel } from "./f1/RelatedPanel";
import { StoryTab } from "./f2/StoryTab";
import { AnalystTab } from "./f3/AnalystTab";

/** Incident-page tabs contributed by features; only tabs of enabled features are shown. */
export const INCIDENT_TABS: IncidentTab[] = [
  { featureId: "f2", id: "story", label: "Story", order: 5, Component: StoryTab },
  { featureId: "f3", id: "analyst", label: "AI analyst", order: 6, Component: AnalystTab },
  { featureId: "f1", id: "related", label: "Related", order: 60, Component: RelatedPanel },
];

export function enabledIncidentTabs(manifest: FeatureManifestEntry[], tabs: IncidentTab[] = INCIDENT_TABS): IncidentTab[] {
  const enabled = new Set(manifest.map((feature) => feature.id));
  return tabs.filter((tab) => enabled.has(tab.featureId)).sort((a, b) => a.order - b.order);
}
