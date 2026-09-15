import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useLiveEvents } from "../../core/useLiveEvents";
import "./prediction.css";

interface Toast {
  id: string;
  incidentId: string;
  techniqueId: string;
}

/** Live alert when a watched prediction comes true anywhere in the workspace. */
export function PredictionAlerts() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  useLiveEvents(["prediction"], (message) => {
    if (message.event !== "prediction.observed") return;
    const payload = message.data as { incident_id?: string; prediction_id?: string; technique_id?: string } | null;
    const id = payload?.prediction_id;
    const incidentId = payload?.incident_id;
    if (!id || !incidentId) return;
    setToasts((current) => [...current.filter((t) => t.id !== id), { id, incidentId, techniqueId: payload.technique_id ?? "" }].slice(-4));
  });

  useEffect(() => {
    if (toasts.length === 0) return;
    const timer = window.setTimeout(() => setToasts((current) => current.slice(1)), 20_000);
    return () => window.clearTimeout(timer);
  }, [toasts]);

  if (toasts.length === 0) return null;
  return (
    <div className="toasts" role="status" aria-live="polite">
      {toasts.map((toast) => (
        <div key={toast.id} className="toast">
          <div>
            <strong>Prediction observed</strong>
            <div className="small">
              {toast.techniqueId} on <Link to={`/incidents/${toast.incidentId}`}>incident {toast.incidentId.slice(0, 8)}</Link>
            </div>
          </div>
          <button type="button" className="ghost" aria-label="Dismiss alert" onClick={() => setToasts((current) => current.filter((t) => t.id !== toast.id))}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
