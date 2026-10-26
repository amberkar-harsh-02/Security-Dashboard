import { useId, useState } from "react";
import { useElementWidth } from "../hooks/useElementWidth";
import { niceMax } from "../lib/chart";
import { formatClock } from "../lib/format";
import "./LineChart.css";

// A live time-series chart: 2px lines over a light wash, hairline grid, crosshair with one
// tooltip for every series, keyboard readout and a table view. In `sparkline` mode it is a
// small decorative line with no axes or interaction (the value is shown next to it in text).

const MARGIN = { top: 8, right: 8, bottom: 22, left: 52 };

function linePath(points, x, y) {
  return points.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ");
}

function formatTime(t) {
  return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/**
 * series: [{ key, label, color }], where color is a CSS variable name like "--series-1".
 * points: [{ t: epoch ms, [key]: number }], oldest first.
 */
export default function LineChart({
  title,
  series,
  points,
  windowMs,
  max,
  formatValue = String,
  height = 220,
  sparkline = false,
}) {
  const [wrapRef, width] = useElementWidth(sparkline ? 120 : 600);
  const [active, setActive] = useState(null);
  const [showTable, setShowTable] = useState(false);
  const tableId = useId();

  const end = points.length ? points[points.length - 1].t : Date.now();
  const start = end - windowMs;
  const visible = points.filter((p) => p.t >= start);
  const margin = sparkline ? { top: 2, right: 1, bottom: 2, left: 1 } : MARGIN;
  const plotWidth = Math.max(10, width - margin.left - margin.right);
  const plotHeight = Math.max(10, height - margin.top - margin.bottom);
  const peak = Math.max(0, ...visible.flatMap((p) => series.map((s) => p[s.key] ?? 0)));
  const yMax = max ?? niceMax(peak, 1);

  const x = (t) => margin.left + ((t - start) / windowMs) * plotWidth;
  const y = (value) => margin.top + plotHeight - (Math.min(value, yMax) / yMax) * plotHeight;
  const baseline = margin.top + plotHeight;

  const lines = series.map((s) => {
    const values = visible.map((p) => ({ t: p.t, value: p[s.key] ?? 0 }));
    const path = values.length ? linePath(values, x, y) : "";
    const area = values.length > 1 ? `${path} L${x(values.at(-1).t)},${baseline} L${x(values[0].t)},${baseline} Z` : "";
    return { ...s, path, area };
  });

  if (sparkline) {
    return (
      <div className="line-chart line-chart--spark" ref={wrapRef} aria-hidden="true">
        <svg width={width} height={height}>
          {lines.map((line) => (
            <g key={line.key} style={{ "--series-color": `var(${line.color})` }}>
              {line.area && <path className="line-chart__area" d={line.area} />}
              {line.path && <path className="line-chart__line line-chart__line--thin" d={line.path} />}
            </g>
          ))}
        </svg>
      </div>
    );
  }

  const activePoint = active !== null ? visible[active] : null;
  const ticks = [0, yMax / 2, yMax];
  const timeTicks = [start, start + windowMs / 2, end];

  function nearest(clientX, box) {
    const t = start + ((clientX - box.left - margin.left) / plotWidth) * windowMs;
    let best = null;
    visible.forEach((p, i) => {
      if (best === null || Math.abs(p.t - t) < Math.abs(visible[best].t - t)) best = i;
    });
    return best;
  }

  function onKeyDown(event) {
    if (!visible.length) return;
    const current = active ?? visible.length - 1;
    const moves = { ArrowLeft: current - 1, ArrowRight: current + 1, Home: 0, End: visible.length - 1 };
    if (event.key in moves) {
      event.preventDefault();
      setActive(Math.max(0, Math.min(visible.length - 1, moves[event.key])));
    }
  }

  const tooltipLeft = activePoint ? x(activePoint.t) : 0;
  const tooltipOnLeft = tooltipLeft > width / 2;

  return (
    <figure className="line-chart">
      <div className="line-chart__head">
        {series.length > 1 && (
          <ul className="line-chart__legend" aria-label="Series">
            {series.map((s) => (
              <li key={s.key}>
                <span className="line-chart__key" style={{ background: `var(${s.color})` }} aria-hidden="true" />
                {s.label}
              </li>
            ))}
          </ul>
        )}
        <button
          type="button"
          className="button button--quiet line-chart__toggle"
          aria-expanded={showTable}
          aria-controls={tableId}
          onClick={() => setShowTable((value) => !value)}
        >
          {showTable ? "Hide table" : "Show as table"}
        </button>
      </div>

      <div className="line-chart__plot" ref={wrapRef}>
        <div
          className="line-chart__interactive"
          role="group"
          tabIndex={0}
          aria-label={`${title}. Use the left and right arrow keys to read values.`}
          onPointerMove={(event) => setActive(nearest(event.clientX, event.currentTarget.getBoundingClientRect()))}
          onPointerLeave={() => setActive(null)}
          onBlur={() => setActive(null)}
          onKeyDown={onKeyDown}
        >
          <svg width={width} height={height} aria-hidden="true">
            {ticks.map((tick) => (
              <g key={tick}>
                <line className="line-chart__grid" x1={margin.left} x2={width - margin.right} y1={y(tick)} y2={y(tick)} />
                <text className="line-chart__axis" x={margin.left - 8} y={y(tick)} dy="0.32em" textAnchor="end">
                  {formatValue(tick)}
                </text>
              </g>
            ))}
            {timeTicks.map((t, i) => (
              <text
                key={t}
                className="line-chart__axis"
                x={x(t)}
                y={baseline + 15}
                textAnchor={i === 0 ? "start" : i === 2 ? "end" : "middle"}
              >
                {formatClock(t)}
              </text>
            ))}
            {lines.map((line) => (
              <g key={line.key} style={{ "--series-color": `var(${line.color})` }}>
                {line.area && <path className="line-chart__area" d={line.area} />}
                {line.path && <path className="line-chart__line" d={line.path} />}
              </g>
            ))}
            {activePoint && (
              <g>
                <line className="line-chart__crosshair" x1={x(activePoint.t)} x2={x(activePoint.t)} y1={margin.top} y2={baseline} />
                {series.map((s) => (
                  <circle
                    key={s.key}
                    className="line-chart__dot"
                    style={{ "--series-color": `var(${s.color})` }}
                    cx={x(activePoint.t)}
                    cy={y(activePoint[s.key] ?? 0)}
                    r={4}
                  />
                ))}
              </g>
            )}
          </svg>
          {!visible.length && <p className="line-chart__empty">Collecting the first samples…</p>}
        </div>

        {activePoint && (
          <div
            className={`line-chart__tooltip${tooltipOnLeft ? " line-chart__tooltip--left" : ""}`}
            style={{ left: tooltipOnLeft ? tooltipLeft - 10 : tooltipLeft + 10, top: margin.top }}
            aria-hidden="true"
          >
            <div className="line-chart__tooltip-time">{formatTime(activePoint.t)}</div>
            {series.map((s) => (
              <div key={s.key} className="line-chart__tooltip-row">
                <span className="line-chart__tooltip-key" style={{ background: `var(${s.color})` }} />
                <strong>{formatValue(activePoint[s.key] ?? 0)}</strong> {s.label.toLowerCase()}
              </div>
            ))}
          </div>
        )}
        <p className="visually-hidden" aria-live="polite">
          {activePoint
            ? `${formatTime(activePoint.t)}: ${series.map((s) => `${s.label} ${formatValue(activePoint[s.key] ?? 0)}`).join(", ")}`
            : ""}
        </p>
      </div>

      {showTable && (
        <div className="line-chart__table-wrap" id={tableId}>
          <table className="line-chart__table">
            <caption className="visually-hidden">{title}</caption>
            <thead>
              <tr>
                <th scope="col">Time</th>
                {series.map((s) => (
                  <th key={s.key} scope="col" className="num">
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[...visible].reverse().map((p) => (
                <tr key={p.t}>
                  <th scope="row">{formatTime(p.t)}</th>
                  {series.map((s) => (
                    <td key={s.key} className="num">
                      {formatValue(p[s.key] ?? 0)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </figure>
  );
}
