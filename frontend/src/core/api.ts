export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export type QueryValue = string | number | boolean | null | undefined;
export type Query = Record<string, QueryValue>;

export interface ApiClient {
  get<T>(path: string, query?: Query): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
  put<T>(path: string, body?: unknown): Promise<T>;
  patch<T>(path: string, body?: unknown): Promise<T>;
  delete<T>(path: string, body?: unknown): Promise<T>;
  text(path: string, query?: Query): Promise<string>;
}

export interface ApiClientOptions {
  baseUrl?: string;
  getToken: () => string | null;
  onUnauthorized?: () => void;
  fetchImpl?: typeof fetch;
}

export function buildUrl(baseUrl: string, path: string, query?: Query): string {
  const params = new URLSearchParams();
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") {
        params.set(key, String(value));
      }
    }
  }
  const search = params.toString();
  return `${baseUrl}${path}${search ? `?${search}` : ""}`;
}

interface ErrorPayload {
  error?: { code?: string; message?: string; details?: unknown };
}

export function createApiClient(options: ApiClientOptions): ApiClient {
  const baseUrl = options.baseUrl ?? "/api";
  const fetchImpl: typeof fetch = options.fetchImpl ?? ((input, init) => fetch(input, init));

  async function request(method: string, path: string, body?: unknown, query?: Query): Promise<Response> {
    const headers: Record<string, string> = { Accept: "application/json" };
    const token = options.getToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    const init: RequestInit = { method, headers, credentials: "omit", cache: "no-store" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const response = await fetchImpl(buildUrl(baseUrl, path, query), init);
    if (!response.ok) {
      let code = "http_error";
      let message = `Request failed (${response.status})`;
      let details: unknown;
      try {
        const payload = (await response.json()) as ErrorPayload;
        if (payload.error) {
          code = payload.error.code ?? code;
          message = payload.error.message ?? message;
          details = payload.error.details;
        }
      } catch {
        // Non-JSON error body: keep the generic message.
      }
      if (response.status === 401) {
        options.onUnauthorized?.();
      }
      throw new ApiError(response.status, code, message, details);
    }
    return response;
  }

  async function json<T>(method: string, path: string, body?: unknown, query?: Query): Promise<T> {
    const response = await request(method, path, body, query);
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }

  return {
    get: <T>(path: string, query?: Query) => json<T>("GET", path, undefined, query),
    post: <T>(path: string, body?: unknown) => json<T>("POST", path, body ?? {}),
    put: <T>(path: string, body?: unknown) => json<T>("PUT", path, body ?? {}),
    patch: <T>(path: string, body?: unknown) => json<T>("PATCH", path, body ?? {}),
    delete: <T>(path: string, body?: unknown) => json<T>("DELETE", path, body),
    text: async (path: string, query?: Query) => (await request("GET", path, undefined, query)).text(),
  };
}
