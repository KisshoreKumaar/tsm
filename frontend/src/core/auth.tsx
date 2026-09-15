import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { createApiClient, type ApiClient } from "./api";
import type { Principal } from "./types";

export interface AuthContextValue {
  principal: Principal | null;
  api: ApiClient;
  getToken: () => string | null;
  login: (token: string) => Promise<void>;
  lock: () => void;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children, fetchImpl }: { children: ReactNode; fetchImpl?: typeof fetch }) {
  // The token lives only in this ref: never in storage, cookies, URLs or rendered state.
  const tokenRef = useRef<string | null>(null);
  const [principal, setPrincipal] = useState<Principal | null>(null);

  const getToken = useCallback(() => tokenRef.current, []);
  const lock = useCallback(() => {
    tokenRef.current = null;
    setPrincipal(null);
  }, []);
  const api = useMemo(
    () => createApiClient({ getToken, onUnauthorized: lock, ...(fetchImpl ? { fetchImpl } : {}) }),
    [getToken, lock, fetchImpl],
  );
  const login = useCallback(
    async (token: string) => {
      tokenRef.current = token.trim();
      try {
        setPrincipal(await api.get<Principal>("/me"));
      } catch (error) {
        tokenRef.current = null;
        setPrincipal(null);
        throw error;
      }
    },
    [api],
  );
  const can = useCallback((permission: string) => principal?.permissions.includes(permission) ?? false, [principal]);

  const value = useMemo<AuthContextValue>(
    () => ({ principal, api, getToken, login, lock, can }),
    [principal, api, getToken, login, lock, can],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return value;
}
