import { NavLink, Outlet } from "react-router-dom";
import { buildNav } from "../featureManifest";
import { useAuth } from "./auth";

export function Layout() {
  const { principal, lock } = useAuth();
  if (!principal) {
    return null;
  }
  const sections = buildNav(principal.features);
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
          <div className="topbar-status" />
          <div className="identity">
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
    </div>
  );
}
