import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import AlertBand, { isTick, selectionIndexes } from "./AlertBand";

const HOUR = 3600;
const start = Date.UTC(2026, 9, 19, 0, 0, 0) / 1000;
const series = Array.from({ length: 6 }, (_, i) => ({
  start: start + i * HOUR,
  critical: i === 2 ? 1 : 0,
  high: i === 2 ? 3 : 0,
  medium: i === 4 ? 2 : 0,
  low: 0,
  info: 0,
}));
const events = series.map((b, i) => ({ start: b.start, events: 10 * (i + 1) }));

describe("selectionIndexes", () => {
  const buckets = series.map((b) => ({ startMs: b.start * 1000 }));
  it("maps a time window onto the buckets it overlaps", () => {
    const from = new Date((start + HOUR) * 1000).toISOString();
    const to = new Date((start + 3 * HOUR) * 1000).toISOString();
    expect(selectionIndexes(buckets, HOUR * 1000, { from, to })).toEqual([1, 2]);
  });
  it("returns null without a selection or overlap", () => {
    expect(selectionIndexes(buckets, HOUR * 1000, null)).toBeNull();
    expect(selectionIndexes(buckets, HOUR * 1000, { from: "2000-01-01T00:00:00Z", to: "2000-01-02T00:00:00Z" })).toBeNull();
  });
});

describe("isTick", () => {
  it("labels whole hours on hourly buckets and day starts on 6-hour buckets", () => {
    const localMidnight = new Date(2026, 9, 19, 0, 0, 0).getTime();
    expect(isTick(localMidnight, HOUR, 50)).toBe(true);
    expect(isTick(localMidnight + 60 * 60 * 1000, HOUR, 50)).toBe(false); // 1:00 with labels every 2 h
    expect(isTick(localMidnight, 6 * HOUR, 40)).toBe(true);
    expect(isTick(localMidnight + 6 * 60 * 60 * 1000, 6 * HOUR, 40)).toBe(false);
  });
});

describe("AlertBand", () => {
  function setup(selection = null) {
    const onSelect = vi.fn();
    const onClear = vi.fn();
    render(
      <AlertBand series={series} events={events} bucketSeconds={HOUR} selection={selection} onSelect={onSelect} onClear={onClear} />,
    );
    return { onSelect, onClear, plot: screen.getByRole("group", { name: /Alerts over time/ }) };
  }

  it("reads each period with the arrow keys and selects it with Enter", () => {
    const { onSelect, plot } = setup();
    fireEvent.keyDown(plot, { key: "Home" });
    fireEvent.keyDown(plot, { key: "ArrowRight" });
    fireEvent.keyDown(plot, { key: "ArrowRight" });
    expect(screen.getByText(/4 alerts, 1 critical, 3 high, 0 medium, 0 low, 30 events/)).toBeInTheDocument();

    fireEvent.keyDown(plot, { key: "Enter" });
    expect(onSelect).toHaveBeenCalledWith(
      new Date((start + 2 * HOUR) * 1000).toISOString(),
      new Date((start + 3 * HOUR) * 1000).toISOString(),
    );
  });

  it("clears the selection with Escape", () => {
    const { onClear, plot } = setup({
      from: new Date(start * 1000).toISOString(),
      to: new Date((start + HOUR) * 1000).toISOString(),
    });
    fireEvent.keyDown(plot, { key: "Escape" });
    expect(onClear).toHaveBeenCalled();
  });

  it("offers the same data as a table", () => {
    setup();
    fireEvent.click(screen.getByRole("button", { name: "Show as table" }));
    const rows = screen.getAllByRole("row");
    expect(rows).toHaveLength(series.length + 1);
  });

  it("explains an empty range", () => {
    const empty = series.map((b) => ({ ...b, critical: 0, high: 0, medium: 0 }));
    render(<AlertBand series={empty} events={events} bucketSeconds={HOUR} onSelect={() => {}} onClear={() => {}} />);
    expect(screen.getByText(/No alerts in this range/)).toBeInTheDocument();
  });
});
