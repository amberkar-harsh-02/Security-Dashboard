import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import LineChart from "../components/LineChart";
import { fakeBackend, lastQuery } from "../test/fakeBackend";
import Performance from "./Performance";

const NOW = Date.UTC(2026, 9, 19, 12, 0, 0);

function point(secondsAgo, cpu) {
  return {
    t: NOW - secondsAgo * 1000,
    cpu,
    cores: [cpu, cpu / 2],
    mem_used: 4 * 1024 ** 3,
    mem_percent: 50,
    swap_percent: 0,
    disk_read: 2048,
    disk_write: 1024,
    net_recv: 5 * 1024 ** 2,
    net_sent: 1024 ** 2,
  };
}

function snapshot(history) {
  return {
    info: { hostname: "siem-host", os: "Linux 5.15", cores_logical: 2, cores_physical: 2, cpu_mhz: 2400, memory_total: 8 * 1024 ** 3, boot_time: 0 },
    interval_seconds: 2,
    uptime_seconds: 3 * 86400 + 4 * 3600,
    load: [0.5, 0.4, 0.3],
    history,
    disks: [{ mount: "/", fstype: "ext4", total: 80 * 1024 ** 3, used: 8 * 1024 ** 3, percent: 92 }],
    processes: {
      count: 120,
      top: [
        { pid: 10, name: "waitress-serve", user: "siem", cpu: 4.5, memory: 90 * 1024 ** 2 },
        { pid: 11, name: "caddy", user: "caddy", cpu: 1.0, memory: 300 * 1024 ** 2 },
      ],
    },
  };
}

let fetchMock;
beforeEach(() => {
  fetchMock = fakeBackend({
    "GET /performance": () => [200, snapshot([point(400, 10), point(120, 30), point(2, 40)])],
  });
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => vi.unstubAllGlobals());

function renderPage() {
  return render(
    <MemoryRouter>
      <Performance />
    </MemoryRouter>,
  );
}

describe("Performance page", () => {
  it("shows CPU first, with machine facts and processes", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: "CPU" })).toBeInTheDocument();
    expect(screen.getByText(/siem-host, Linux 5.15/)).toBeInTheDocument();
    expect(screen.getByText("2.40 GHz", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getByText("3 d 4 h")).toBeInTheDocument();
    expect(screen.getByText("Core 2")).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "waitress-serve" })).toBeInTheDocument();
  });

  it("switches resources by click and with the arrow keys", async () => {
    renderPage();
    const cpuTab = await screen.findByRole("tab", { name: /CPU/ });
    expect(cpuTab).toHaveAttribute("aria-selected", "true");

    await userEvent.setup().click(screen.getByRole("tab", { name: /Disk/ }));
    expect(screen.getByRole("heading", { name: "Disk" })).toBeInTheDocument();
    expect(screen.getByRole("meter", { name: "/ space used" })).toHaveAttribute("aria-valuenow", "92");

    fireEvent.keyDown(screen.getByRole("tab", { name: /Disk/ }), { key: "ArrowDown" });
    expect(screen.getByRole("tab", { name: /Network/ })).toHaveFocus();
    expect(screen.getByRole("heading", { name: "Network" })).toBeInTheDocument();
    expect(screen.getByText("5.0 MB/s", { selector: "dd" })).toBeInTheDocument();
  });

  it("asks only for new samples after the first load", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderPage();
    await screen.findByRole("heading", { name: "CPU" });
    await vi.advanceTimersByTimeAsync(2100);
    await waitFor(() => expect(lastQuery(fetchMock, "/performance").get("since")).toBe(String(NOW - 2000)));
    vi.useRealTimers();
  });

  it("sorts processes by memory", async () => {
    renderPage();
    await screen.findByRole("cell", { name: "waitress-serve" });
    const table = screen.getByRole("heading", { name: "Top processes" }).closest("section");
    await userEvent.setup().click(within(table).getByRole("button", { name: "Memory" }));
    const names = within(table).getAllByRole("row").slice(1).map((row) => row.cells[0].textContent);
    expect(names).toEqual(["caddy", "waitress-serve"]);
  });
});

describe("LineChart", () => {
  it("keeps only the window and offers the same values as a table", async () => {
    const points = [point(400, 10), point(120, 30), point(2, 40)];
    render(
      <LineChart
        title="CPU"
        series={[{ key: "cpu", label: "Utilization", color: "--series-1" }]}
        points={points}
        windowMs={5 * 60 * 1000}
        max={100}
        formatValue={(v) => `${v}%`}
      />,
    );
    await userEvent.setup().click(screen.getByRole("button", { name: "Show as table" }));
    const cells = screen.getAllByRole("row").slice(1).map((row) => row.cells[1].textContent);
    expect(cells).toEqual(["40%", "30%"]); // the 400-second-old point is outside 5 minutes

    const plot = screen.getByRole("group", { name: /CPU/ });
    fireEvent.keyDown(plot, { key: "End" });
    expect(screen.getByText(/Utilization 40%/)).toBeInTheDocument();
  });
});
