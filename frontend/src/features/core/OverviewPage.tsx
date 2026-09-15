import { useAuth } from "../../core/auth";

export function OverviewPage() {
  const { principal } = useAuth();
  if (!principal) {
    return null;
  }
  return (
    <section>
      <h1>Overview</h1>
      <p className="muted">
        Signed in as {principal.name} ({principal.role}).
      </p>
      <h2>Enabled features</h2>
      <ul className="feature-list">
        {principal.features.map((feature) => (
          <li key={feature.id}>
            <strong>{feature.name}</strong> <span className="muted">{feature.description}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
