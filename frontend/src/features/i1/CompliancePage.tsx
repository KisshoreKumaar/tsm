import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../core/auth";
import { errorMessage, formatTime } from "../../core/format";
import { Card, EmptyState, ErrorBanner, Loading, SeverityBadge, StatusBadge } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import { useLiveEvents } from "../../core/useLiveEvents";
import { DeadlineBadge } from "./DeadlineBadge";
import type { DeadlineRow, OrgProfile } from "./types";
import "./compliance.css";

const EMPTY: OrgProfile = {
  organization_name: "",
  sector: "",
  contact_name: "",
  contact_email: "",
  contact_phone: "",
  address: "",
  updated_by: "",
  updated_at: "",
};

function ProfileCard({ profile, configured, onSaved }: { profile: OrgProfile | null; configured: boolean; onSaved: () => void }) {
  const { api, can } = useAuth();
  const [form, setForm] = useState<OrgProfile>(profile ?? EMPTY);
  const [editing, setEditing] = useState(!configured);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.put("/org-profile", {
        organization_name: form.organization_name,
        sector: form.sector,
        contact_name: form.contact_name,
        contact_email: form.contact_email,
        contact_phone: form.contact_phone,
        address: form.address || null,
      });
      setEditing(false);
      onSaved();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const set = (key: keyof OrgProfile) => (event: { target: { value: string } }) =>
    setForm((current) => ({ ...current, [key]: event.target.value }));

  return (
    <Card
      title="Organisation profile"
      actions={
        can("settings.manage") &&
        !editing && (
          <button type="button" className="ghost" onClick={() => setEditing(true)}>
            Edit
          </button>
        )
      }
    >
      {!configured && (
        <div className="warning-banner small">
          No organisation profile is saved. CERT-In drafts will be missing the reporter details until an administrator
          fills this in.
        </div>
      )}
      {editing && can("settings.manage") ? (
        <form className="form" onSubmit={submit}>
          <div className="provider-grid">
            <label className="field">
              Organisation name
              <input value={form.organization_name} maxLength={200} onChange={set("organization_name")} required />
            </label>
            <label className="field">
              Sector
              <input value={form.sector} maxLength={120} onChange={set("sector")} required />
            </label>
            <label className="field">
              Point of contact
              <input value={form.contact_name} maxLength={120} onChange={set("contact_name")} required />
            </label>
            <label className="field">
              Contact email
              <input value={form.contact_email} maxLength={200} onChange={set("contact_email")} required />
            </label>
            <label className="field">
              Contact phone
              <input value={form.contact_phone} maxLength={40} onChange={set("contact_phone")} required />
            </label>
            <label className="field">
              Address
              <input value={form.address ?? ""} maxLength={400} onChange={set("address")} />
            </label>
          </div>
          {error && (
            <p role="alert" className="error">
              {error}
            </p>
          )}
          <div className="form-row">
            <button type="submit" disabled={busy}>
              {busy ? "Saving…" : "Save profile"}
            </button>
            {configured && (
              <button type="button" className="ghost" onClick={() => setEditing(false)}>
                Cancel
              </button>
            )}
          </div>
        </form>
      ) : (
        profile && (
          <table className="table compact">
            <tbody>
              <tr>
                <td>Organisation</td>
                <td>
                  {profile.organization_name} · {profile.sector}
                </td>
              </tr>
              <tr>
                <td>Contact</td>
                <td>
                  {profile.contact_name} · {profile.contact_email} · {profile.contact_phone}
                </td>
              </tr>
              <tr>
                <td>Address</td>
                <td>{profile.address || "—"}</td>
              </tr>
              <tr>
                <td>Updated</td>
                <td className="muted small">
                  {profile.updated_by} · {formatTime(profile.updated_at)}
                </td>
              </tr>
            </tbody>
          </table>
        )
      )}
    </Card>
  );
}

export function CompliancePage() {
  const deadlines = useApiQuery<{ items: DeadlineRow[]; template: string | null; profile: boolean }>(
    "/compliance/deadlines",
    { limit: 50 },
  );
  const profile = useApiQuery<{ configured: boolean; profile: OrgProfile | null }>("/org-profile");
  useLiveEvents(["report", "incident"], () => deadlines.refetch());

  return (
    <section>
      <h1>Compliance</h1>
      <p className="muted">
        Reporting deadlines for open incidents and their CERT-In drafts. AEGIS prepares drafts from evidence and tracks
        the clock; a human reviews, approves and files every report through the official channel.
      </p>
      {deadlines.data?.template && <div className="warning-banner">{deadlines.data.template}</div>}
      <ErrorBanner error={deadlines.error ?? profile.error} />
      {profile.data && (
        <ProfileCard profile={profile.data.profile} configured={profile.data.configured} onSaved={profile.refetch} />
      )}
      <Card title="Incidents with reporting deadlines">
        {deadlines.loading && !deadlines.data && <Loading />}
        {deadlines.data?.items.length === 0 && <EmptyState>No open incidents.</EmptyState>}
        {deadlines.data && deadlines.data.items.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Deadline</th>
                <th>Incident</th>
                <th>Incident status</th>
                <th>Draft</th>
              </tr>
            </thead>
            <tbody>
              {deadlines.data.items.map((row) => (
                <tr key={row.incident_id}>
                  <td>
                    <DeadlineBadge deadline={row.deadline} />
                  </td>
                  <td>
                    <SeverityBadge severity={row.severity} />{" "}
                    <Link to={`/incidents/${row.incident_id}`}>{row.title}</Link>
                  </td>
                  <td>
                    <StatusBadge status={row.incident_status} />
                  </td>
                  <td>
                    {row.report_status ? (
                      <StatusBadge status={row.report_status} />
                    ) : (
                      <Link to={`/incidents/${row.incident_id}`} className="small">
                        prepare a draft
                      </Link>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </section>
  );
}
