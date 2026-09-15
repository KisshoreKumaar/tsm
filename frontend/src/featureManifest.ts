import type { ComponentType } from "react";
import type { FeatureManifestEntry, FeatureNav } from "./core/types";
import { OverviewPage } from "./features/core/OverviewPage";

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
 * so a disabled feature has neither routes nor navigation entries here.
 */
export const FRONTEND_FEATURES: FrontendFeature[] = [{ id: "core", routes: [{ path: "/overview", Component: OverviewPage }] }];

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
