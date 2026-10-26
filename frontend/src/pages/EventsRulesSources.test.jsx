import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { AuthProvider } from "../auth/AuthProvider";
import { LiveProvider } from "../hooks/useLive";
import { clearLookups } from "../hooks/useLookups";
import { TimeRangeProvider } from "../hooks/useTimeRange";
import { FakeEventSource, fakeBackend, lastQuery } from "../test/fakeBackend";
import Events from "./Events";
import Rules, { toYaml } from "./Rules";
import Sources, { isQuiet } from "./Sources";

const NOW = new Date().toISOString();
const EVENTS = [
  {
    id: 1,
    ts: NOW,
    severity: "low",
    host: "web-01",
    source: "sshd",
    outcome: "failure",
    user: "root",
    src_ip: "203.0.113.9",
    message: "Failed password for root from 203.0.113.9",
    raw: "<38>Oct 19 web-01 sshd[1]: Failed password for root from 203.0.113.9",
  },
];
const RULES = [
  {
    id: "port-scan",
    name: "Port scan",
    description: "One address connected to many ports.",
    severity: "medium",
    type: "distinct",
    enabled: true,
    group_by: ["src_ip"],
    window_seconds: 60,
    threshold: 25,
    field: "dst_port",
    mitre: { technique: "T1046", name: "Network Service Discovery" },
    alerts_24h: 3,
    definition: { id: "port-scan", type: "distinct", group_by: ["src_ip"] },
  },
  {
    id: "web-attack",
    name: "Web application attack",
    description: "Attack patterns in web requests.",
    severity: "high",
    type: "match",
    enabled: false,
    group_by: ["src_ip"],
    window_seconds: 300,
    threshold: 1,
    mitre: {},
    alerts_24h: 0,
    definition: { id: "web-attack" },
  },
];

function Where() {
  const location = useLocation();
  return <output data-testid="where">{location.pathname + location.search + location.hash}</output>;
}

function renderAt(path, element, routePath) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <TimeRangeProvider>
          <LiveProvider>
            <Routes>
              <Route path={routePath} element={element} />
            </Routes>
            <Where />
          </LiveProvider>
        </TimeRangeProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

let fetchMock;
let routes;
beforeEach(() => {
  clearLookups();
  vi.stubGlobal("EventSource", FakeEventSource);
  routes = {
    "GET /auth/me": () => [200, { user: "admin", csrf_token: "t" }],
    "GET /events": () => [200, { events: EVENTS, total: 1, page: 1, limit: 100 }],
    "GET /sources": () => [
      200,
      {
        sources: [
          { source: "sshd", host: "web-01", events_24h: 120, events_1h: 10, last_seen: NOW },
          { source: "firewall", host: "fw-01", events_24h: 60, events_1h: 0, last_seen: new Date(Date.now() - 3600e3).toISOString() },
        ],
        collectors: {
          syslog: { enabled: true, host: "127.0.0.1", port: 5514 },
          host_agent: { enabled: true, interval_seconds: 10 },
          simulator: { enabled: true, noise_per_second: 0.5 },
          ingest_api: { path: "/api/ingest", raw_path: "/api/ingest/raw", default_key: true },
        },
      },
    ],
    "GET /system-health": () => [200, { cpu: 12, memory: 40, disk: 70 }],
    "GET /rules": () => [200, { rules: RULES }],
    "PATCH /rules/port-scan": (init) => [200, { ...RULES[0], enabled: JSON.parse(init.body).enabled }],
    "POST /rules/reload": () => [400, { error: "bad.yml (bad): type must be one of match, threshold" }],
  };
  fetchMock = fakeBackend(routes);
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => vi.unstubAllGlobals());

describe("Events page", () => {
  it("searches with filters from the URL and the form", async () => {
    renderAt("/events?ip=203.0.113.9", <Events />, "/events");
    expect(await screen.findByText("Failed password for root from 203.0.113.9")).toBeInTheDocument();
    expect(lastQuery(fetchMock, "/events").get("ip")).toBe("203.0.113.9");
    expect(lastQuery(fetchMock, "/events").get("from")).toBeTruthy();

    const user = userEvent.setup();
    await user.type(screen.getByRole("searchbox", { name: /Text in the message/ }), "failed password");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(lastQuery(fetchMock, "/events").get("q")).toBe("failed password"));

    const tokens = screen.getByRole("list", { name: "Active filters" });
    await user.click(within(tokens).getByRole("button", { name: "Remove address filter" }));
    await waitFor(() => expect(lastQuery(fetchMock, "/events").get("ip")).toBeNull());
    expect(screen.getByTestId("where")).toHaveTextContent("/events?q=failed+password");
  });

  it("pivots on a field value without losing other filters", async () => {
    renderAt("/events?q=failed", <Events />, "/events");
    await screen.findByText("Failed password for root from 203.0.113.9");
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Show details for event 1" }));
    expect(screen.getByText(/<38>Oct 19 web-01 sshd/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "root" })).toHaveAttribute("href", "/events?q=failed&user=root");
    expect(screen.getByRole("link", { name: "203.0.113.9" })).toHaveAttribute("href", "/events?q=failed&ip=203.0.113.9");
  });

  it("explains an empty result", async () => {
    routes["GET /events"] = () => [200, { events: [], total: 0, page: 1, limit: 100 }];
    renderAt("/events?user=nobody", <Events />, "/events");
    expect(await screen.findByText(/No events match/)).toBeInTheDocument();
  });
});

describe("Rules page", () => {
  it("lists rules with their trigger and turns one off", async () => {
    renderAt("/rules", <Rules />, "/rules");
    expect(await screen.findByRole("heading", { name: "Port scan" })).toBeInTheDocument();
    expect(screen.getByText("2 rules, 1 on")).toBeInTheDocument();
    expect(screen.getByText(/25 or more different dst_port values appear within 1 minute/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /3 alerts/ })).toHaveAttribute("href", "/alerts?status=all&rule_id=port-scan");

    const toggle = screen.getByRole("switch", { name: "Port scan: on" });
    await userEvent.setup().click(toggle);
    expect(await screen.findByText("Port scan is off.")).toBeInTheDocument();
    const patch = fetchMock.mock.calls.find(([, init]) => init.method === "PATCH");
    expect(JSON.parse(patch[1].body)).toEqual({ enabled: false });
    expect(screen.getByRole("switch", { name: "Port scan: off" })).toHaveAttribute("aria-checked", "false");
  });

  it("keeps the old rules when a reload fails", async () => {
    renderAt("/rules", <Rules />, "/rules");
    await screen.findByRole("heading", { name: "Port scan" });
    await userEvent.setup().click(screen.getByRole("button", { name: "Reload rule files" }));
    expect(await screen.findByText(/Rule files not reloaded. The previous rules stay active. bad.yml/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Port scan" })).toBeInTheDocument();
  });

  it("marks the rule named in the address", async () => {
    Element.prototype.scrollIntoView = vi.fn();
    renderAt("/rules#web-attack", <Rules />, "/rules");
    await screen.findByRole("heading", { name: "Web application attack" });
    expect(document.getElementById("web-attack")).toHaveClass("rule--target");
    expect(Element.prototype.scrollIntoView).toHaveBeenCalled();
  });

  it("drops the trailing newline of folded text but keeps meaningful spaces", () => {
    expect(toYaml({ description: "Many failed logins.\n", "message|contains": "(possible " })).toBe(
      'description: Many failed logins.\nmessage|contains: "(possible "',
    );
  });

  it("renders definitions as YAML", () => {
    expect(toYaml({ id: "x", where: { "message|contains": "(possible " }, group_by: ["src_ip"], threshold: 5 })).toBe(
      'id: x\nwhere:\n  message|contains: "(possible "\ngroup_by: [src_ip]\nthreshold: 5',
    );
  });
});

describe("Sources page", () => {
  it("flags quiet sources and explains how logs arrive", async () => {
    renderAt("/sources", <Sources />, "/sources");
    expect(await screen.findByRole("link", { name: "firewall" })).toHaveAttribute("href", "/events?source=firewall&host=fw-01");
    expect(screen.getByText("1 quiet for over 15 minutes")).toBeInTheDocument();
    expect(screen.getByText(/udp:\/\/127.0.0.1:5514/)).toBeInTheDocument();
    expect(screen.getByText(/ingest key is still the default/)).toBeInTheDocument();
  });

  it("decides quietness from the last event time", () => {
    const now = Date.parse("2026-10-19T12:00:00Z");
    expect(isQuiet("2026-10-19T11:50:00Z", now)).toBe(false);
    expect(isQuiet("2026-10-19T11:40:00Z", now)).toBe(true);
  });
});
