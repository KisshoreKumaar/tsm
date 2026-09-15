import type { ComponentType } from "react";
import type { FeatureManifestEntry, FeatureNav } from "./core/types";
import { AuditPage } from "./features/core/AuditPage";
import { DemoPage } from "./features/core/DemoPage";
import { EventsPage } from "./features/core/EventsPage";
import { IncidentPage } from "./features/core/IncidentPage";
import { IncidentsPage } from "./features/core/IncidentsPage";
import { OverviewPage } from "./features/core/OverviewPage";
import { ResponsesPage } from "./features/core/ResponsesPage";
import { RulesPage } from "./features/core/RulesPage";
import { CampaignPage } from "./features/f1/CampaignPage";
import { CampaignsPage } from "./features/f1/CampaignsPage";
import { GraphPage } from "./features/f1/GraphPage";
import { AiProvidersPage } from "./features/x1/AiProvidersPage";
import { AiStatusPage } from "./features/x1/AiStatusPage";
import { ProposalsPage } from "./features/x2/ProposalsPage";

export interface FrontendRoute {
  path: string;
  Component: ComponentType;
}

export interface FrontendFeature {
  id: string;
  routes: FrontendRoute[];
}

/**
 * Frontend half of each feature. The server's manifest (GET /api/me) decides which features are enabled,
 * so a disabled feature has neither routes nor navigation entries here. Incident-page tabs contributed by
 * features are registered in `features/incidentTabs.ts`.
 */
export const FRONTEND_FEATURES: FrontendFeature[] = [
  {
    id: "core",
    routes: [
      { path: "/overview", Component: OverviewPage },
      { path: "/incidents", Component: IncidentsPage },
      { path: "/incidents/:id", Component: IncidentPage },
      { path: "/events", Component: EventsPage },
      { path: "/responses", Component: ResponsesPage },
      { path: "/rules", Component: RulesPage },
      { path: "/demo", Component: DemoPage },
      { path: "/audit", Component: AuditPage },
    ],
  },
  {
    id: "f1",
    routes: [
      { path: "/campaigns", Component: CampaignsPage },
      { path: "/campaigns/:id", Component: CampaignPage },
      { path: "/graph", Component: GraphPage },
    ],
  },
  {
    id: "x1",
    routes: [
      { path: "/ai/status", Component: AiStatusPage },
      { path: "/settings/ai-providers", Component: AiProvidersPage },
    ],
  },
  {
    id: "x2",
    routes: [{ path: "/agent/proposals", Component: ProposalsPage }],
  },
];

export function enabledRoutes(
  manifest: FeatureManifestEntry[],
  features: FrontendFeature[] = FRONTEND_FEATURES,
): FrontendRoute[] {
  const enabled = new Set(manifest.map((feature) => feature.id));
  return features.filter((feature) => enabled.has(feature.id)).flatMap((feature) => feature.routes);
}

export interface NavSection {
  name: string;
  items: FeatureNav[];
}

const SECTION_ORDER = ["Operations", "Investigation", "Detection", "Compliance", "AI", "Governance", "Settings"];

export function buildNav(manifest: FeatureManifestEntry[]): NavSection[] {
  const bySection = new Map<string, FeatureNav[]>();
  for (const feature of manifest) {
    for (const item of feature.nav) {
      const items = bySection.get(item.section) ?? [];
      items.push(item);
      bySection.set(item.section, items);
    }
  }
  const rank = (name: string) => {
    const index = SECTION_ORDER.indexOf(name);
    return index === -1 ? SECTION_ORDER.length : index;
  };
  return [...bySection.entries()]
    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
    .map(([name, items]) => ({
      name,
      items: [...items].sort((x, y) => x.order - y.order || x.label.localeCompare(y.label)),
    }));
}
