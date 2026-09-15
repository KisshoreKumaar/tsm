import type { ReactNode } from "react";
import { errorMessage } from "./format";

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge sev-${severity.toLowerCase()}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge status-${status.toLowerCase()}`}>{status.replace("_", " ")}</span>;
}

export function ClaimLabel({ label }: { label: string }) {
  return <span className={`badge claim-${label.toLowerCase()}`}>{label}</span>;
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) {
    return null;
  }
  return (
    <div role="alert" className="error-banner">
      {errorMessage(error)}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return <p className="muted">{label}</p>;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Pagination({
  offset,
  limit,
  total,
  onChange,
}: {
  offset: number;
  limit: number;
  total: number;
  onChange: (offset: number) => void;
}) {
  if (total <= limit) {
    return null;
  }
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="pagination">
      <button type="button" className="ghost" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
        Previous
      </button>
      <span className="muted">
        Page {page} of {pages} ({total} total)
      </span>
      <button type="button" className="ghost" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>
        Next
      </button>
    </div>
  );
}

export interface TabItem<T extends string> {
  id: T;
  label: string;
}

export function Tabs<T extends string>({ tabs, active, onChange }: { tabs: TabItem<T>[]; active: T; onChange: (id: T) => void }) {
  return (
    <div role="tablist" className="tabs">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={tab.id === active}
          className={tab.id === active ? "tab active" : "tab"}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

export function Card({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="card-header">
          {title && <h2>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function KeyValues({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([key, value]) => (
        <div key={key}>
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}
