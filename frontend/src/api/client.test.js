import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, buildQuery, setCsrfToken, setUnauthorizedHandler } from "./client";

function respond(status, body) {
  return vi.fn().mockResolvedValue({ status, ok: status < 400, json: () => Promise.resolve(body) });
}

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken(null);
  setUnauthorizedHandler(() => {});
});

describe("buildQuery", () => {
  it("skips empty values and joins lists", () => {
    expect(buildQuery({ q: "root", page: 2, severity: ["high", "critical"], user: null, ip: undefined, tags: [] })).toBe(
      "?q=root&page=2&severity=high%2Ccritical",
    );
    expect(buildQuery({})).toBe("");
  });
});

describe("api", () => {
  it("sends the CSRF token on writes only", async () => {
    const fetchMock = respond(200, { ok: true });
    vi.stubGlobal("fetch", fetchMock);
    setCsrfToken("token-1");

    await api.get("/alerts", { status: "open" });
    await api.patch("/alerts/3", { status: "closed" });

    const [getUrl, getInit] = fetchMock.mock.calls[0];
    expect(getUrl).toBe("/api/alerts?status=open");
    expect(getInit.headers["X-CSRF-Token"]).toBeUndefined();

    const [, patchInit] = fetchMock.mock.calls[1];
    expect(patchInit.method).toBe("PATCH");
    expect(patchInit.headers["X-CSRF-Token"]).toBe("token-1");
    expect(JSON.parse(patchInit.body)).toEqual({ status: "closed" });
  });

  it("raises the server's error message", async () => {
    vi.stubGlobal("fetch", respond(400, { error: "status: must be one of open, acknowledged, closed" }));
    await expect(api.patch("/alerts/1", { status: "x" })).rejects.toMatchObject({
      name: "ApiError",
      status: 400,
      message: "status: must be one of open, acknowledged, closed",
    });
  });

  it("calls the unauthorized handler on 401, except for sign-in", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    vi.stubGlobal("fetch", respond(401, { error: "Sign in to continue" }));

    await expect(api.get("/alerts")).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledTimes(1);

    await expect(api.post("/auth/login", { username: "a", password: "b" })).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("explains when the backend is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(api.get("/alerts")).rejects.toMatchObject({ status: 0, message: expect.stringContaining("port 5000") });
  });
});
