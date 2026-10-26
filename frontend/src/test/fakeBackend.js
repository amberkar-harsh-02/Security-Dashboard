import { vi } from "vitest";

/**
 * A fetch stub. `routes` maps "METHOD /path" to (init, url) => [status, body].
 * Every call is recorded in `fetch.mock.calls`.
 */
export function fakeBackend(routes) {
  return vi.fn(async (url, init = {}) => {
    const path = url.replace(/^\/api/, "").split("?")[0];
    const method = init.method || "GET";
    const handler = routes[`${method} ${path}`];
    const [status, body] = handler ? handler(init, url) : [404, { error: `no fake for ${method} ${path}` }];
    return { status, ok: status < 400, json: async () => body };
  });
}

export class FakeEventSource {
  addEventListener() {}
  close() {}
}

/** Query parameters of the last call to `path`. */
export function lastQuery(fetchMock, path) {
  const call = [...fetchMock.mock.calls].reverse().find(([url]) => url.split("?")[0] === `/api${path}`);
  return call ? new URLSearchParams(call[0].split("?")[1] ?? "") : null;
}
