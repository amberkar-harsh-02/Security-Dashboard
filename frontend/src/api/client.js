// Thin wrapper over fetch for the SIEM API.
// The dev server proxies /api to Flask, so requests are same-origin and carry the session cookie.

// BASE_URL is "/" in development and "/siem/" when built for the Caddy server.
export const API_BASE = `${import.meta.env.BASE_URL}api`;

let csrfToken = null;
let onUnauthorized = () => {};

export class ApiError extends Error {
  constructor(message, status, data = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

export function setCsrfToken(token) {
  csrfToken = token;
}

/** Called when any request (other than sign-in) gets 401, so the app can return to sign-in. */
export function setUnauthorizedHandler(handler) {
  onUnauthorized = handler;
}

export function buildQuery(params = {}) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      if (value.length) query.set(key, value.join(","));
    } else {
      query.set(key, String(value));
    }
  }
  const text = query.toString();
  return text ? `?${text}` : "";
}

async function request(method, path, { body, params, signal } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  let response;
  try {
    response = await fetch(`${API_BASE}${path}${buildQuery(params)}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      signal,
    });
  } catch (error) {
    if (error.name === "AbortError") throw error;
    throw new ApiError("Cannot reach the SIEM backend. Check that it is running on port 5000.", 0);
  }

  const data = await response.json().catch(() => null);
  if (response.status === 401 && path !== "/auth/login") onUnauthorized();
  if (!response.ok) {
    throw new ApiError(data?.error || `Request failed with status ${response.status}`, response.status, data);
  }
  return data;
}

export const api = {
  get: (path, params, options) => request("GET", path, { ...options, params }),
  post: (path, body, options) => request("POST", path, { ...options, body: body ?? {} }),
  patch: (path, body, options) => request("PATCH", path, { ...options, body }),
};
