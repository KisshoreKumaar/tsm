import { useState, type FormEvent } from "react";
import { ApiError } from "./api";
import { useAuth } from "./auth";

export function LoginPage() {
  const { login } = useAuth();
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(token);
    } catch (err) {
      setToken("");
      setError(
        err instanceof ApiError && err.status === 401 ? "That token was not accepted." : "Could not reach the AEGIS API.",
      );
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form className="login-card" onSubmit={submit}>
        <h1>
          AEGIS <span>SOC</span>
        </h1>
        <p className="muted">AI-assisted security operations. Evidence first; humans decide.</p>
        <label htmlFor="token">Operator token</label>
        <input
          id="token"
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={token}
          onChange={(event) => setToken(event.target.value)}
        />
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy || token.trim().length === 0}>
          {busy ? "Connecting…" : "Connect"}
        </button>
        <p className="hint">The token is kept in memory only. Reloading the page or pressing Lock clears it.</p>
      </form>
    </main>
  );
}
