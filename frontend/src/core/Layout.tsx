import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { buildNav } from "../featureManifest";
import { PredictionAlerts } from "../features/f4/PredictionAlerts";
import { AiStatusChip } from "../features/x1/AiStatusChip";
import { AgentDrawer } from "../features/x2/AgentDrawer";
import { useAuth } from "./auth";

export function Layout() {
  const { principal, lock, can } = useAuth();
  const [agentOpen, setAgentOpen] = useState(false);
  if (!principal) {
    return null;
  }
  const sections = buildNav(principal.features);
  const enabled = new Set(principal.features.map((feature) => feature.id));
  const agentAvailable = enabled.has("x2") && can("ai.use");
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          AEGIS <span>SOC</span>
        </div>
        <nav aria-label="Main">
          {sections.map((section) => (
            <div key={section.name} className="nav-section">
              <div className="nav-heading">{section.name}</div>
              {section.items.map((item) => (
                <NavLink key={item.path} to={item.path} className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="topbar-status">{enabled.has("x1") && can("read") && <AiStatusChip />}</div>
          <div className="identity">
            {agentAvailable && (
              <button type="button" className={agentOpen ? "" : "ghost"} aria-pressed={agentOpen} onClick={() => setAgentOpen((open) => !open)}>
                Agent
              </button>
            )}
            <span className="badge">{principal.role}</span>
            <span>{principal.name}</span>
            <button type="button" className="ghost" onClick={lock}>
              Lock
            </button>
          </div>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
      {enabled.has("f4") && can("read") && <PredictionAlerts />}
      {agentAvailable && agentOpen && <AgentDrawer onClose={() => setAgentOpen(false)} />}
    </div>
  );
}
