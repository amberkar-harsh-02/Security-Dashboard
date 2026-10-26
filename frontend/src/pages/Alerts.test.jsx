import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { AuthProvider } from "../auth/AuthProvider";
import { LiveProvider } from "../hooks/useLive";
import { clearLookups } from "../hooks/useLookups";
import { TimeRangeProvider } from "../hooks/useTimeRange";
import { FakeEventSource, fakeBackend, lastQuery } from "../test/fakeBackend";
import Alerts from "./Alerts";

const recent = new Date().toISOString();
const ALERTS = [
  {
    id: 7,
    severity: "critical",
    title: "admin logged in from 203.0.113.9 after repeated failures",
    rule_name: "Successful login after repeated failures",
    status: "open",
    assignee: null,
    event_count: 26,
    last_seen: recent,
  },
  {
    id: 6,
    severity: "high",
    title: "SSH brute force from 203.0.113.9",
    rule_name: "SSH brute force",
    status: "open",
    assignee: "admin",
    event_count: 25,
    last_seen: recent,
  },
  {
    id: 5,
    severity: "medium",
    title: "Port scan from 203.0.113.4",
    rule_name: "Port scan",
    status: "acknowledged",
    assignee: null,
    event_count: 60,
    last_seen: recent,
  },
];

function Where() {
  const location = useLocation();
  return <output data-testid="where">{location.pathname + location.search}</output>;
}

function renderAlerts(path = "/alerts") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <TimeRangeProvider>
          <LiveProvider>
            <Routes>
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/alerts/:id" element={<p>Detail page</p>} />
            </Routes>
            <Where />
          </LiveProvider>
        </TimeRangeProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function backend(alerts = ALERTS) {
  return fakeBackend({
    "GET /auth/me": () => [200, { user: "admin", csrf_token: "t" }],
    "GET /auth/users": () => [200, { users: ["admin", "bob"] }],
    "GET /rules": () => [200, { rules: [{ id: "port-scan", name: "Port scan" }] }],
    "GET /alerts": () => [200, { alerts, total: alerts.length, page: 1, limit: 50 }],
    "POST /alerts/bulk": (init) => [200, { changed: JSON.parse(init.body).ids }],
  });
}

let fetchMock;
beforeEach(() => {
  clearLookups();
  vi.stubGlobal("EventSource", FakeEventSource);
  fetchMock = backend();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => vi.unstubAllGlobals());

describe("Alerts page", () => {
  it("lists open alerts by default and keeps filters in the URL", async () => {
    renderAlerts();
    expect(await screen.findByText("SSH brute force from 203.0.113.9")).toBeInTheDocument();
    expect(lastQuery(fetchMock, "/alerts").get("status")).toBe("open");

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Critical" }));
    await waitFor(() => expect(lastQuery(fetchMock, "/alerts").get("severity")).toBe("critical"));
    expect(screen.getByTestId("where")).toHaveTextContent("/alerts?severity=critical");

    await user.click(screen.getByRole("radio", { name: "All" }));
    await waitFor(() => expect(lastQuery(fetchMock, "/alerts").get("status")).toBeNull());

    await user.selectOptions(screen.getByRole("combobox", { name: "Assignee" }), "none");
    await waitFor(() => expect(lastQuery(fetchMock, "/alerts").get("assignee")).toBe(""));
  });

  it("reads filters from the URL", async () => {
    renderAlerts("/alerts?rule_id=port-scan&status=closed");
    await screen.findByText("Port scan from 203.0.113.4");
    const query = lastQuery(fetchMock, "/alerts");
    expect(query.get("rule_id")).toBe("port-scan");
    expect(query.get("status")).toBe("closed");
  });

  it("closes selected alerts in one request", async () => {
    renderAlerts();
    await screen.findByText("SSH brute force from 203.0.113.9");
    const user = userEvent.setup();
    await user.click(screen.getByRole("checkbox", { name: /Select SSH brute force/ }));
    await user.click(screen.getByRole("checkbox", { name: /Select Port scan/ }));
    expect(screen.getByText("2 selected")).toBeInTheDocument();

    const bar = screen.getByRole("region", { name: "Selected alerts" });
    await user.click(within(bar).getByRole("button", { name: "Close" }));
    const call = fetchMock.mock.calls.find(([url, init]) => url === "/api/alerts/bulk" && init.method === "POST");
    expect(JSON.parse(call[1].body)).toEqual({ ids: [6, 5], status: "closed" });
    expect(call[1].headers["X-CSRF-Token"]).toBe("t");
    expect(await screen.findByText("2 alerts marked closed.")).toBeInTheDocument();
    expect(screen.queryByText("2 selected")).not.toBeInTheDocument();
  });

  it("moves with j and k, selects with x and opens with Enter", async () => {
    renderAlerts();
    await screen.findByText("SSH brute force from 203.0.113.9");
    const rows = screen.getAllByRole("row").slice(1);
    rows[0].focus();
    fireEvent.keyDown(rows[0], { key: "j" });
    expect(rows[1]).toHaveFocus();
    fireEvent.keyDown(rows[1], { key: "x" });
    expect(screen.getByRole("checkbox", { name: /Select SSH brute force/ })).toBeChecked();
    fireEvent.keyDown(rows[1], { key: "k" });
    expect(rows[0]).toHaveFocus();
    fireEvent.keyDown(rows[0], { key: "Enter" });
    expect(await screen.findByText("Detail page")).toBeInTheDocument();
    expect(screen.getByTestId("where")).toHaveTextContent("/alerts/7");
  });

  it("offers a way out of an empty result", async () => {
    fetchMock = backend([]);
    vi.stubGlobal("fetch", fetchMock);
    renderAlerts("/alerts?severity=low");
    expect(await screen.findByText("No alerts match these filters.")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Show all alerts" }));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/alerts?status=all"));
  });
});
