import { useCallback, useEffect, useState } from "react";
import type { Query } from "./api";
import { useAuth } from "./auth";

export interface QueryState<T> {
  data: T | null;
  error: unknown;
  loading: boolean;
  refetch: () => void;
}

/** GET a resource; keeps the previous data while re-fetching so live refreshes do not flicker. */
export function useApiQuery<T>(path: string | null, query?: Query): QueryState<T> {
  const { api } = useAuth();
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(path !== null);
  const [tick, setTick] = useState(0);
  const key = JSON.stringify([path, query ?? null]);

  useEffect(() => {
    if (path === null) {
      return;
    }
    let cancelled = false;
    setLoading(true);
    api
      .get<T>(path, query)
      .then((result) => {
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
    // `key` captures path and query.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, key, tick]);

  const refetch = useCallback(() => setTick((value) => value + 1), []);
  return { data, error, loading, refetch };
}
