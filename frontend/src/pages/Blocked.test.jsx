import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { AuthProvider } from "../auth/AuthProvider";
import { LiveProvider } from "../hooks/useLive";
import { clearLookups } from "../hooks/useLookups";
import { formatTimeLeft } from "../lib/blocks";
import { FakeEventSource, fakeBackend } from "../test/fakeBackend";
import AlertDetail from "./AlertDetail";
import Blocked from "./Blocked";
import Rules from "./Rules";

const NOW = new Date().toISOString();
const inMinutes = (m) => new Date(Date.now() + m * 60000).toISOString();

let fetchMock;
let routes;
beforeEach(() => {
  clearLookups();
  vi.stubGlobal("EventSource", FakeEventSource);
  routes = {
    "GET /auth/me": () => [200, { user: "admin", csrf_token: "t" }],
    "GET /auth/users": () => [200, { users: ["admin"] }],
  };
  fetchMock = fakeBackend(routes);
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => vi.unstubAllGlobals());

function renderAt(path, element, routePath) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <LiveProvider>
          <Routes>
            <Route path={routePath} element={element} />
          </Routes>
        </LiveProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function lastCall(method, path) {
  const call = fetchMock.mock.calls.filter(([url, init]) => url.startsWith(`/api${path}`) && init.method === method).at(-1);
  return call ? { url: call[0], init: call[1], body: call[1].body ? JSON.parse(call[1].body) : null } : null;
}

describe("formatTimeLeft", () => {
  it("reads like a countdown", () => {
    const now = Date.parse("2026-10-20T12:00:00Z");
    expect(formatTimeLeft("2026-10-20T12:42:00Z", now)).toBe("42 min left");
    expect(formatTimeLeft("2026-10-20T17:00:00Z", now)).toBe("5 h left");
    expect(formatTimeLeft("2026-10-27T12:00:00Z", now)).toBe("7 days left");
    expect(formatTimeLeft(null, now)).toBe("Permanent");
  });
});

describe("Blocked page", () => {
  beforeEach(() => {
    let active = [
      { id: 1, ip: "203.0.113.9", reason: "guessing SSH passwords", created_by: "rule:ssh-brute-force", created_at: NOW, expires_at: inMinutes(50), active: true },
    ];
    routes["GET /blocks"] = () => [200, { enforcement: { mode: "firewall", last_applied_at: NOW, applied: 1, skipped: 0, error: null }, durations: [15, 60, 1440, 10080, null], active, history: [] }];
    routes["POST /blocks/1/unblock"] = () => {
      active = [];
      return [200, { id: 1, ip: "203.0.113.9", active: false }];
    };
    routes["POST /blocks"] = (init) => {
      const body = JSON.parse(init.body);
      if (body.ip === "203.0.113.200") return [400, { error: "This is your own address. Blocking it would lock you out." }];
      return [201, { id: 2, ip: body.ip, active: true }];
    };
  });

  it("lists active blocks with who blocked them and time left, and unblocks", async () => {
    renderAt("/blocked", <Blocked />, "/blocked");
    expect(await screen.findByText(/Enforced by the server firewall/)).toBeInTheDocument();
    const row = screen.getByRole("link", { name: "203.0.113.9" }).closest("tr");
    expect(within(row).getByText("Auto-block (ssh-brute-force)")).toBeInTheDocument();
    expect(within(row).getByText(/min left/)).toBeInTheDocument();

    await userEvent.setup().click(within(row).getByRole("button", { name: "Unblock" }));
    expect(await screen.findByText("Unblocked 203.0.113.9.")).toBeInTheDocument();
    expect(await screen.findByText(/No addresses are blocked/)).toBeInTheDocument();
  });

  it("pre-fills from the address bar, posts with CSRF and shows refusals", async () => {
    renderAt("/blocked?ip=203.0.113.200", <Blocked />, "/blocked");
    const address = await screen.findByLabelText("Address");
    expect(address).toHaveValue("203.0.113.200");

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Block" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("This is your own address");

    await user.clear(address);
    await user.type(address, "198.51.100.23");
    await user.selectOptions(screen.getByLabelText("For"), "Permanently");
    await user.click(screen.getByRole("button", { name: "Block" }));
    expect(await screen.findByText("Blocked 198.51.100.23.")).toBeInTheDocument();
    const call = lastCall("POST", "/blocks");
    expect(call.body).toEqual({ ip: "198.51.100.23", minutes: null, reason: "" });
    expect(call.init.headers["X-CSRF-Token"]).toBe("t");
  });

  it("says when blocks are only recorded", async () => {
    routes["GET /blocks"] = () => [200, { enforcement: { mode: "record-only" }, durations: [], active: [], history: [] }];
    renderAt("/blocked", <Blocked />, "/blocked");
    expect(await screen.findByText(/recorded but not enforced/)).toBeInTheDocument();
  });
});

describe("Blocking from an alert", () => {
  function alertWith(blocked) {
    return {
      id: 4, rule_id: "port-scan", rule_name: "Port scan", severity: "medium", title: "Port scan from 203.0.113.4",
      status: "open", assignee: null, group_fields: { src_ip: "203.0.113.4" }, event_count: 0,
      first_seen: NOW, last_seen: NOW, created_at: NOW, rule: null, events: [], notes: [], blocked,
    };
  }

  it("blocks the source for the chosen time and then offers to unblock", async () => {
    let blocked = null;
    routes["GET /alerts/4"] = () => [200, alertWith(blocked)];
    routes["POST /blocks"] = () => {
      blocked = { id: 9, ip: "203.0.113.4", expires_at: inMinutes(1440) };
      return [201, blocked];
    };
    renderAt("/alerts/4", <AlertDetail />, "/alerts/:id");
    await screen.findByRole("heading", { name: "Port scan from 203.0.113.4" });

    const user = userEvent.setup();
    await user.selectOptions(screen.getByRole("combobox", { name: /Block 203.0.113.4 for/ }), "24 hours");
    await user.click(screen.getByRole("button", { name: "Block" }));
    expect(lastCall("POST", "/blocks").body).toEqual({ ip: "203.0.113.4", minutes: 1440, reason: "Port scan from 203.0.113.4", alert_id: 4 });
    expect(await screen.findByText(/is blocked until/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Unblock" })).toBeInTheDocument();
  });
});

describe("Auto-block on the Rules page", () => {
  it("is offered only for rules that group by source address and PATCHes the choice", async () => {
    const rule = (id, name, canAuto) => ({
      id, name, description: "", severity: "high", type: "threshold", enabled: true, group_by: canAuto ? ["src_ip"] : ["host"],
      window_seconds: 120, threshold: 10, mitre: {}, alerts_24h: 0, definition: { id }, can_auto_block: canAuto, auto_block_minutes: null,
    });
    routes["GET /rules"] = () => [200, { rules: [rule("ssh-brute-force", "SSH brute force", true), rule("audit-log-cleared", "Audit log cleared", false)] }];
    routes["PATCH /rules/ssh-brute-force"] = (init) => [200, { ...rule("ssh-brute-force", "SSH brute force", true), ...JSON.parse(init.body) }];
    renderAt("/rules", <Rules />, "/rules");
    await screen.findByRole("heading", { name: "SSH brute force" });

    const selects = screen.getAllByRole("combobox", { name: /Auto-block the source/ });
    expect(selects).toHaveLength(1);
    await userEvent.setup().selectOptions(selects[0], "1 hour");
    await waitFor(() => expect(lastCall("PATCH", "/rules/ssh-brute-force").body).toEqual({ auto_block_minutes: 60 }));
    expect(await screen.findByText(/now blocks the source address for 1 hour/)).toBeInTheDocument();
  });
});
