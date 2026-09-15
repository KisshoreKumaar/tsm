export interface FeatureNav {
  path: string;
  label: string;
  section: string;
  permission: string;
  order: number;
}

export interface FeatureManifestEntry {
  id: string;
  name: string;
  description: string;
  nav: FeatureNav[];
}

export interface Principal {
  name: string;
  role: string;
  permissions: string[];
  features: FeatureManifestEntry[];
  two_person: boolean;
  version: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
}
