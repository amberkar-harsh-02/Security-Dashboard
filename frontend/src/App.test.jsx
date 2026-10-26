import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "./auth/AuthProvider";
import { AppRoutes } from "./App";

// Fake backend: routes keyed by "METHOD /path".
function fakeBackend(routes) {
  return vi.fn(async (url, init = {}) => {
    const path = url.replace(/^\/api/, "").split("?")[0];
    const handler = routes[`${init.method || "GET"} ${path}`];
    const [status, body] = handler ? handler(init) : [404, { error: "not found" }];
    return { status, ok: status < 400, json: async () => body };
  });
}

function renderAt(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </MemoryRouter>,
  );
}

class FakeEventSource {
  addEventListener() {}
  close() {}
}

beforeEach(() => {
  vi.stubGlobal("EventSource", FakeEventSource);
  window.matchMedia = window.matchMedia || (() => ({ matches: false }));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("sign-in", () => {
  it("sends signed-out visitors to sign-in, then back to the page they asked for", async () => {
    let signedIn = false;
    vi.stubGlobal(
      "fetch",
      fakeBackend({
        "GET /auth/me": () => (signedIn ? [200, { user: "admin", csrf_token: "t" }] : [401, { error: "Sign in to continue" }]),
        "POST /auth/login": (init) => {
          const body = JSON.parse(init.body);
          if (body.password !== "correct-horse-battery") return [401, { error: "Username or password is incorrect" }];
          signedIn = true;
          return [200, { user: "admin", csrf_token: "t" }];
        },
      }),
    );

    renderAt("/rules");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();

    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Username or password is incorrect");

    await user.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Rules" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
  });

  it("shows the app shell for a signed-in analyst", async () => {
    vi.stubGlobal("fetch", fakeBackend({ "GET /auth/me": () => [200, { user: "admin", csrf_token: "t" }] }));
    renderAt("/");
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    for (const name of ["Overview", "Alerts", "Events", "Rules", "Sources"]) {
      expect(screen.getByRole("link", { name })).toBeInTheDocument();
    }
    expect(screen.getByRole("search")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "24h" })).toBeChecked();
  });
});
