import { useId, useMemo, useRef, useState } from "react";
import { useElementWidth } from "../hooks/useElementWidth";
import { niceMax } from "../lib/chart";
import { formatClock, formatCompact, formatDay, formatNumber, formatSpan, SEVERITY_LABELS } from "../lib/format";
import "./AlertBand.css";

// Alerts per time bucket, stacked by severity, with event volume on its own strip below
// (same time axis, separate scale: never two y-axes on one plot).
// Drag across the plot, or use the arrow keys and Enter, to choose a period.

const STACK = ["info", "low", "medium", "high", "critical"]; // bottom to top
const LEGEND = ["critical", "high", "medium", "low"];
const MARGIN = { left: 36, right: 8, top: 10 };
const PLOT_HEIGHT = 140;
const AXIS_HEIGHT = 22;
const STRIP_HEIGHT = 40;
const STRIP_GAP = 14;
const GAP = 2; // surface gap between stacked segments
const RADIUS = 4;

function topRoundedRect(x, y, w, h, r) {
  const radius = Math.min(r, w / 2, h);
  return [
    `M${x},${y + h}`,
    `V${y + radius}`,
    `Q${x},${y} ${x + radius},${y}`,
    `H${x + w - radius}`,
    `Q${x + w},${y} ${x + w},${y + radius}`,
    `V${y + h}`,
    "Z",
  ].join(" ");
}

/** Should bucket `start` (ms) carry an x-axis label, given the bucket size and slot width? */
export function isTick(startMs, stepSeconds, slot) {
  const date = new Date(startMs);
  if (stepSeconds >= 6 * 3600) return date.getHours() < stepSeconds / 3600;
  if (stepSeconds >= 3600) {
    const every = slot >= 40 ? 2 : slot >= 20 ? 3 : 6;
    return date.getMinutes() === 0 && date.getHours() % every === 0;
  }
  const minutes = slot >= 30 ? 10 : 20;
  return date.getMinutes() % minutes === 0;
}

function tickLabel(startMs, stepSeconds) {
  return stepSeconds >= 6 * 3600 ? formatDay(startMs) : formatClock(startMs);
}

/** Bucket indexes covered by a {from, to} selection, or null. */
export function selectionIndexes(buckets, stepMs, selection) {
  if (!selection?.from) return null;
  const from = Date.parse(selection.from);
  const to = Date.parse(selection.to);
  let first = -1;
  let last = -1;
  buckets.forEach((bucket, index) => {
    if (bucket.startMs + stepMs > from && bucket.startMs < to) {
      if (first === -1) first = index;
      last = index;
    }
  });
  return first === -1 ? null : [first, last];
}

export default function AlertBand({ series, events, bucketSeconds, selection, onSelect, onClear, dimmed }) {
  const [wrapRef, width] = useElementWidth();
  const [active, setActive] = useState(null); // hovered or focused bucket index
  const [drag, setDrag] = useState(null); // {anchor, current, moved}
  const [showTable, setShowTable] = useState(false);
  const plotRef = useRef(null);
  const tableId = useId();
  const hintId = useId();

  const stepMs = bucketSeconds * 1000;
  const buckets = useMemo(
    () =>
      series.map((bucket, index) => ({
        ...bucket,
        startMs: bucket.start * 1000,
        total: STACK.reduce((sum, s) => sum + (bucket[s] || 0), 0),
        events: events[index]?.events ?? 0,
      })),
    [series, events],
  );

  const n = buckets.length || 1;
  const plotWidth = Math.max(0, width - MARGIN.left - MARGIN.right);
  const slot = plotWidth / n;
  const barWidth = Math.max(2, Math.min(24, slot - GAP));
  const maxTotal = Math.max(0, ...buckets.map((b) => b.total));
  const yMax = niceMax(maxTotal);
  const scale = PLOT_HEIGHT / yMax;
  const baseline = MARGIN.top + PLOT_HEIGHT;
  const maxEvents = Math.max(1, ...buckets.map((b) => b.events));
  const stripTop = baseline + AXIS_HEIGHT + STRIP_GAP;
  const height = stripTop + STRIP_HEIGHT + 4;
  const totalAlerts = buckets.reduce((sum, b) => sum + b.total, 0);

  const barX = (index) => MARGIN.left + index * slot + (slot - barWidth) / 2;
  const indexAt = (clientX) => {
    const box = plotRef.current.getBoundingClientRect();
    const x = clientX - box.left - MARGIN.left;
    return Math.min(n - 1, Math.max(0, Math.floor(x / slot)));
  };

  const selected = drag
    ? [Math.min(drag.anchor, drag.current), Math.max(drag.anchor, drag.current)]
    : selectionIndexes(buckets, stepMs, selection);

  function commit(first, last) {
    onSelect(new Date(buckets[first].startMs).toISOString(), new Date(buckets[last].startMs + stepMs).toISOString());
  }

  function onPointerDown(event) {
    if (event.button !== 0 || !buckets.length) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    const index = indexAt(event.clientX);
    setDrag({ anchor: index, current: index, moved: false });
  }

  function onPointerMove(event) {
    if (!buckets.length) return;
    const index = indexAt(event.clientX);
    setActive(index);
    if (drag && index !== drag.current) setDrag({ ...drag, current: index, moved: true });
  }

  function onPointerUp() {
    if (!drag) return;
    const first = Math.min(drag.anchor, drag.current);
    const last = Math.max(drag.anchor, drag.current);
    setDrag(null);
    commit(first, last);
  }

  function onKeyDown(event) {
    if (!buckets.length) return;
    const current = active ?? n - 1;
    const moves = { ArrowLeft: current - 1, ArrowRight: current + 1, Home: 0, End: n - 1 };
    if (event.key in moves) {
      event.preventDefault();
      setActive(Math.min(n - 1, Math.max(0, moves[event.key])));
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      commit(current, current);
    } else if (event.key === "Escape" && selection?.from) {
      onClear();
    }
  }

  const activeBucket = active !== null ? buckets[active] : null;
  const ticks = buckets.filter((b) => isTick(b.startMs, bucketSeconds, slot));
  const eventPoints = buckets.map((b, i) => [
    MARGIN.left + i * slot + slot / 2,
    stripTop + STRIP_HEIGHT - (b.events / maxEvents) * (STRIP_HEIGHT - 2),
  ]);
  const eventLine = eventPoints.map(([x, y], i) => `${i ? "L" : "M"}${x},${y}`).join(" ");
  const eventArea = eventPoints.length
    ? `${eventLine} L${eventPoints.at(-1)[0]},${stripTop + STRIP_HEIGHT} L${eventPoints[0][0]},${stripTop + STRIP_HEIGHT} Z`
    : "";

  // The tooltip sits beside the hovered bar, on whichever side has more room.
  const tooltipOnLeft = activeBucket ? barX(active) + barWidth / 2 > width / 2 : false;
  const tooltipLeft = activeBucket ? (tooltipOnLeft ? barX(active) - 10 : barX(active) + barWidth + 10) : 0;

  return (
    <section className={`band${dimmed ? " band--dimmed" : ""}`} aria-labelledby={`${hintId}-title`}>
      <div className="band__head">
        <h2 id={`${hintId}-title`}>Alerts over time</h2>
        <ul className="band__legend" aria-label="Severity colors">
          {LEGEND.map((severity) => (
            <li key={severity}>
              <span className={`band__swatch band__fill--${severity}`} aria-hidden="true" />
              {SEVERITY_LABELS[severity]}
            </li>
          ))}
        </ul>
        <div className="band__actions">
          <span id={hintId} className="band__hint">
            Drag across the chart to focus on a period
          </span>
          <button
            type="button"
            className="button button--quiet"
            aria-expanded={showTable}
            aria-controls={tableId}
            onClick={() => setShowTable((value) => !value)}
          >
            {showTable ? "Hide table" : "Show as table"}
          </button>
        </div>
      </div>

      <div className="band__plot" ref={wrapRef}>
        <div
          className="band__interactive"
          ref={plotRef}
          role="group"
          tabIndex={0}
          aria-label="Alerts over time. Use the left and right arrow keys to read each period, Enter to focus on it, Escape to clear."
          aria-describedby={hintId}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerLeave={() => !drag && setActive(null)}
          onKeyDown={onKeyDown}
          onBlur={() => setActive(null)}
        >
          <svg width={width} height={height} aria-hidden="true">
            {[0, yMax / 2, yMax].map((tick) => {
              const y = baseline - tick * scale;
              return (
                <g key={tick}>
                  <line className="band__grid" x1={MARGIN.left} x2={width - MARGIN.right} y1={y} y2={y} />
                  <text className="band__axis" x={MARGIN.left - 8} y={y} dy="0.32em" textAnchor="end">
                    {formatCompact(tick)}
                  </text>
                </g>
              );
            })}

            {selected && (
              <rect
                className="band__selection"
                x={MARGIN.left + selected[0] * slot}
                y={MARGIN.top - 4}
                width={(selected[1] - selected[0] + 1) * slot}
                height={PLOT_HEIGHT + 4}
              />
            )}

            {activeBucket && (
              <rect className="band__hover" x={MARGIN.left + active * slot} y={MARGIN.top - 4} width={slot} height={PLOT_HEIGHT + 4} />
            )}

            {buckets.map((bucket, index) => {
              const x = barX(index);
              const parts = STACK.filter((s) => bucket[s] > 0);
              let top = baseline;
              return (
                <g key={bucket.start}>
                  {parts.map((severity, k) => {
                    const h = Math.max(3, bucket[severity] * scale);
                    top -= h;
                    const isTop = k === parts.length - 1;
                    if (isTop) {
                      return <path key={severity} className={`band__fill--${severity}`} d={topRoundedRect(x, top, barWidth, h, RADIUS)} />;
                    }
                    return (
                      <rect key={severity} className={`band__fill--${severity}`} x={x} y={top + GAP} width={barWidth} height={h - GAP} />
                    );
                  })}
                </g>
              );
            })}

            <line className="band__baseline" x1={MARGIN.left} x2={width - MARGIN.right} y1={baseline} y2={baseline} />

            {ticks.map((bucket) => {
              const index = buckets.indexOf(bucket);
              return (
                <text key={bucket.start} className="band__axis" x={MARGIN.left + index * slot} y={baseline + 15} textAnchor="start">
                  {tickLabel(bucket.startMs, bucketSeconds)}
                </text>
              );
            })}

            <text className="band__strip-label" x={MARGIN.left - 8} y={stripTop + 4} textAnchor="end">
              Events
            </text>
            <text className="band__axis" x={MARGIN.left - 8} y={stripTop + 18} textAnchor="end">
              {formatCompact(maxEvents)}
            </text>
            <line className="band__grid" x1={MARGIN.left} x2={width - MARGIN.right} y1={stripTop + STRIP_HEIGHT} y2={stripTop + STRIP_HEIGHT} />
            {eventArea && <path className="band__events-area" d={eventArea} />}
            {eventLine && <path className="band__events-line" d={eventLine} />}
            {activeBucket && <circle className="band__events-dot" cx={eventPoints[active][0]} cy={eventPoints[active][1]} r={4} />}
          </svg>

          {totalAlerts === 0 && (
            <p className="band__empty" style={{ top: MARGIN.top + PLOT_HEIGHT / 2 - 12 }}>
              No alerts in this range. Run a scenario to generate test data.
            </p>
          )}
        </div>

        {activeBucket && (
          <div
            className={`band__tooltip${tooltipOnLeft ? " band__tooltip--left" : ""}`}
            style={{ left: tooltipLeft, top: MARGIN.top }}
            aria-hidden="true"
          >
            <div className="band__tooltip-time">{formatSpan(activeBucket.startMs, activeBucket.startMs + stepMs)}</div>
            <div className="band__tooltip-total">
              <strong>{formatNumber(activeBucket.total)}</strong> {activeBucket.total === 1 ? "alert" : "alerts"}
            </div>
            {LEGEND.filter((s) => activeBucket[s] > 0).map((severity) => (
              <div key={severity} className="band__tooltip-row">
                <span className={`band__key band__key--${severity}`} />
                <strong>{activeBucket[severity]}</strong> {SEVERITY_LABELS[severity].toLowerCase()}
              </div>
            ))}
            <div className="band__tooltip-row band__tooltip-events">
              <strong>{formatNumber(activeBucket.events)}</strong> events
            </div>
          </div>
        )}

        <p className="visually-hidden" aria-live="polite">
          {activeBucket
            ? `${formatSpan(activeBucket.startMs, activeBucket.startMs + stepMs)}: ${activeBucket.total} alerts, ${LEGEND.map(
                (s) => `${activeBucket[s] || 0} ${s}`,
              ).join(", ")}, ${activeBucket.events} events.`
            : ""}
        </p>
      </div>

      {showTable && (
        <div className="band__table-wrap" id={tableId}>
          <table className="band__table">
            <caption className="visually-hidden">Alerts and events per period</caption>
            <thead>
              <tr>
                <th scope="col">Period</th>
                {LEGEND.map((s) => (
                  <th key={s} scope="col" className="num">
                    {SEVERITY_LABELS[s]}
                  </th>
                ))}
                <th scope="col" className="num">
                  Events
                </th>
              </tr>
            </thead>
            <tbody>
              {buckets.map((bucket) => (
                <tr key={bucket.start}>
                  <th scope="row">{formatSpan(bucket.startMs, bucket.startMs + stepMs)}</th>
                  {LEGEND.map((s) => (
                    <td key={s} className="num">
                      {bucket[s] || ""}
                    </td>
                  ))}
                  <td className="num">{formatNumber(bucket.events)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
