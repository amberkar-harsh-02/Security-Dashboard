import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { AuthProvider } from "../auth/AuthProvider";
import { LiveProvider } from "../hooks/useLive";
import { clearLookups } from "../hooks/useLookups";
import { FakeEventSource, fakeBackend } from "../test/fakeBackend";
import { describeTrigger, formatWindow } from "../lib/rules";
import AlertDetail from "./AlertDetail";

const NOW = new Date().toISOString();
const ALERT = {
  id: 3,
  rule_id: "ssh-brute-force",
  rule_name: "SSH brute force",
  severity: "high",
  title: "SSH brute force from 203.0.113.9",
  status: "open",
  assignee: null,
  group_fields: { src_ip: "203.0.113.9" },
  mitre_tactic: "Credential Access",
  mitre_technique: "T1110.001",
  mitre_name: "Password Guessing",
  event_count: 2,
  first_seen: NOW,
  last_seen: NOW,
  created_at: NOW,
  rule: {
    id: "ssh-brute-force",
    type: "threshold",
    threshold: 10,
    window_seconds: 120,
    group_by: ["src_ip"],
    description: "Many failed SSH logins.",
  },
  events: [
    {
      id: 11,
      ts: NOW,
      host: "web-01",
      outcome: "failure",
      message: "Failed password for root",
      raw: "<38>Oct 19 sshd: Failed password for root",
      source: "sshd",
      src_ip: "203.0.113.9",
    },
    { id: 12, ts: NOW, host: "web-01", outcome: "failure", message: "Failed password for admin", raw: null, source: "sshd" },
  ],
  notes: [],
};

let state;
let fetchMock;
beforeEach(() => {
  clearLookups();
  state = structuredClone(ALERT);
  vi.stubGlobal("EventSource", FakeEventSource);
  fetchMock = fakeBackend({
    "GET /auth/me": () => [200, { user: "admin", csrf_token: "t" }],
    "GET /auth/users": () => [200, { users: ["admin", "bob"] }],
    "GET /alerts/3": () => [200, state],
    "PATCH /alerts/3": (init) => {
      const changes = JSON.parse(init.body);
      const note = { id: 90 + state.notes.length, kind: "change", author: "admin", body: "Changed", created_at: NOW };
      state = { ...state, ...changes, notes: [...state.notes, note] };
      return [200, state];
    },
    "POST /alerts/3/notes": (init) => {
      const note = { id: 99, kind: "comment", author: "admin", body: JSON.parse(init.body).body, created_at: NOW };
      state = { ...state, notes: [...state.notes, note] };
      return [201, note];
    },
  });
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => vi.unstubAllGlobals());

function renderDetail(path = "/alerts/3") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <LiveProvider>
          <Routes>
            <Route path="/alerts/:id" element={<AlertDetail />} />
          </Routes>
        </LiveProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function lastPatch() {
  const call = fetchMock.mock.calls.filter(([, init]) => init.method === "PATCH").at(-1);
  return JSON.parse(call[1].body);
}

describe("describeTrigger", () => {
  it("explains each rule type in a sentence", () => {
    expect(describeTrigger(ALERT.rule)).toBe(
      "Fires when 10 or more matching events arrive within 2 minutes from the same source address.",
    );
    expect(
      describeTrigger({ type: "distinct", threshold: 25, field: "dst_port", window_seconds: 60, group_by: ["src_ip"] }),
    ).toBe("Fires when 25 or more different dst_port values appear within 1 minute from the same source address.");
    expect(describeTrigger({ type: "match", window_seconds: 600 })).toMatch(/each matching event/);
    expect(formatWindow(86400)).toBe("1 day");
  });
});

describe("Alert detail", () => {
  it("shows the alert, why it fired, and links to related events", async () => {
    renderDetail();
    expect(await screen.findByRole("heading", { name: "SSH brute force from 203.0.113.9" })).toBeInTheDocument();
    expect(screen.getByText(/10 or more matching events/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "203.0.113.9" })).toHaveAttribute("href", "/events?ip=203.0.113.9");
    expect(screen.getByRole("link", { name: /T1110.001/ })).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1110/001/",
    );
  });

  it("changes status and assignee", async () => {
    renderDetail();
    await screen.findByRole("heading", { name: /SSH brute force/ });
    const user = userEvent.setup();

    await user.click(screen.getByRole("radio", { name: "Acknowledged" }));
    await waitFor(() => expect(screen.getByRole("radio", { name: "Acknowledged" })).toBeChecked());
    expect(lastPatch()).toEqual({ status: "acknowledged" });

    await user.click(screen.getByRole("button", { name: "Assign to me" }));
    expect(lastPatch()).toEqual({ assignee: "admin" });
    await waitFor(() => expect(screen.queryByRole("button", { name: "Assign to me" })).not.toBeInTheDocument());
  });

  it("adds a note and shows raw log lines on request", async () => {
    renderDetail();
    await screen.findByRole("heading", { name: /SSH brute force/ });
    const user = userEvent.setup();

    await user.type(screen.getByLabelText("Add a note"), "Blocked 203.0.113.9 at the firewall.");
    await user.click(screen.getByRole("button", { name: "Add note" }));
    expect(await screen.findByText("Blocked 203.0.113.9 at the firewall.")).toBeInTheDocument();
    expect(screen.getByLabelText("Add a note")).toHaveValue("");

    await user.click(screen.getByRole("button", { name: "Show details for event 11" }));
    expect(screen.getByText("<38>Oct 19 sshd: Failed password for root")).toBeInTheDocument();
  });

  it("explains a missing alert", async () => {
    renderDetail("/alerts/404");
    expect(await screen.findByRole("alert")).toHaveTextContent("Alert 404 does not exist");
  });
});
