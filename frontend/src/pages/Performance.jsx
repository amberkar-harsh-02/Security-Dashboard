import { useMemo, useRef, useState } from "react";
import LineChart from "../components/LineChart";
import { usePerformance } from "../hooks/usePerformance";
import { formatBytes, formatDuration, formatNumber, formatRate } from "../lib/format";
import "./Performance.css";

// Task Manager style view of the machine running the SIEM: pick a resource on the left,
// read its live chart and figures on the right, with the busiest processes below.

const WINDOWS = [
  { id: 1, label: "1 min" },
  { id: 5, label: "5 min" },
  { id: 15, label: "15 min" },
  { id: 60, label: "60 min" },
];

const percent = (value) => `${Math.round(value)}%`;

function resources(snapshot, latest) {
  const total = snapshot?.info.memory_total ?? 0;
  return [
    {
      id: "cpu",
      label: "CPU",
      value: latest ? percent(latest.cpu) : "–",
      detail: snapshot?.info.cpu_mhz ? `${(snapshot.info.cpu_mhz / 1000).toFixed(2)} GHz` : null,
      series: [{ key: "cpu", label: "Utilization", color: "--series-1" }],
      max: 100,
      format: percent,
    },
    {
      id: "memory",
      label: "Memory",
      value: latest ? `${formatBytes(latest.mem_used)} / ${formatBytes(total)}` : "–",
      detail: latest ? percent(latest.mem_percent) : null,
      series: [{ key: "mem_percent", label: "In use", color: "--series-1" }],
      max: 100,
      format: percent,
    },
    {
      id: "disk",
      label: "Disk",
      value: latest ? formatRate(latest.disk_read + latest.disk_write) : "–",
      detail: "read and write",
      series: [
        { key: "disk_read", label: "Read", color: "--series-1" },
        { key: "disk_write", label: "Write", color: "--series-2" },
      ],
      format: formatRate,
    },
    {
      id: "network",
      label: "Network",
      value: latest ? formatRate(latest.net_recv + latest.net_sent) : "–",
      detail: "received and sent",
      series: [
        { key: "net_recv", label: "Received", color: "--series-1" },
        { key: "net_sent", label: "Sent", color: "--series-2" },
      ],
      format: formatRate,
    },
  ];
}

function Stat({ label, value }) {
  return (
    <div className="perf-stat">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function Details({ resource, snapshot, latest }) {
  if (!snapshot || !latest) return null;
  const { info } = snapshot;
  if (resource === "cpu") {
    return (
      <dl className="perf-stats">
        <Stat label="Utilization" value={percent(latest.cpu)} />
        <Stat label="Speed" value={info.cpu_mhz ? `${(info.cpu_mhz / 1000).toFixed(2)} GHz` : "–"} />
        <Stat label="Cores" value={`${info.cores_physical ?? "–"} physical, ${info.cores_logical} logical`} />
        <Stat label="Processes" value={formatNumber(snapshot.processes.count)} />
        <Stat label="Up time" value={formatDuration(snapshot.uptime_seconds)} />
        {snapshot.load && <Stat label="Load (1, 5, 15 min)" value={snapshot.load.join("  ")} />}
      </dl>
    );
  }
  if (resource === "memory") {
    return (
      <dl className="perf-stats">
        <Stat label="In use" value={formatBytes(latest.mem_used)} />
        <Stat label="Available" value={formatBytes(info.memory_total - latest.mem_used)} />
        <Stat label="Total" value={formatBytes(info.memory_total)} />
        <Stat label="Swap in use" value={percent(latest.swap_percent)} />
      </dl>
    );
  }
  if (resource === "disk") {
    return (
      <>
        <dl className="perf-stats">
          <Stat label="Read" value={formatRate(latest.disk_read)} />
          <Stat label="Write" value={formatRate(latest.disk_write)} />
        </dl>
        <table className="table perf-disks">
          <caption className="visually-hidden">Space used per drive</caption>
          <thead>
            <tr>
              <th scope="col">Drive</th>
              <th scope="col">Space used</th>
              <th scope="col" className="num">
                Used
              </th>
              <th scope="col" className="num">
                Size
              </th>
            </tr>
          </thead>
          <tbody>
            {snapshot.disks.map((disk) => (
              <tr key={disk.mount}>
                <td className="mono">{disk.mount}</td>
                <td>
                  <span
                    className={`perf-meter${disk.percent >= 90 ? " perf-meter--danger" : disk.percent >= 75 ? " perf-meter--warning" : ""}`}
                    role="meter"
                    aria-label={`${disk.mount} space used`}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={disk.percent}
                  >
                    <span style={{ width: `${disk.percent}%` }} />
                  </span>
                </td>
                <td className="num">{percent(disk.percent)}</td>
                <td className="num">{formatBytes(disk.total)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </>
    );
  }
  return (
    <dl className="perf-stats">
      <Stat label="Received" value={formatRate(latest.net_recv)} />
      <Stat label="Sent" value={formatRate(latest.net_sent)} />
    </dl>
  );
}

function CoreGrid({ history, windowMs, cores }) {
  return (
    <section className="perf-cores" aria-labelledby="cores-heading">
      <h3 id="cores-heading">Each core</h3>
      <ul>
        {Array.from({ length: cores }, (_, i) => {
          const points = history.map((p) => ({ t: p.t, value: p.cores[i] ?? 0 }));
          const current = points.at(-1)?.value ?? 0;
          return (
            <li key={i}>
              <span className="perf-cores__label">
                Core {i + 1} <strong>{percent(current)}</strong>
              </span>
              <LineChart
                title={`Core ${i + 1}`}
                series={[{ key: "value", label: "Utilization", color: "--series-1" }]}
                points={points}
                windowMs={windowMs}
                max={100}
                height={40}
                sparkline
              />
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function Processes({ processes }) {
  const [sort, setSort] = useState("cpu");
  const rows = useMemo(() => [...processes.top].sort((a, b) => b[sort] - a[sort]).slice(0, 10), [processes, sort]);
  const header = (key, label) => (
    <th scope="col" className="num" aria-sort={sort === key ? "descending" : "none"}>
      <button type="button" className="perf-sort" onClick={() => setSort(key)}>
        {label}
        {sort === key && <span aria-hidden="true"> ↓</span>}
      </button>
    </th>
  );
  return (
    <section className="section" aria-labelledby="processes-heading">
      <div className="section__head">
        <h2 id="processes-heading">Top processes</h2>
        <span className="muted">{formatNumber(processes.count)} running</span>
      </div>
      <table className="table perf-processes">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col" className="num">
              PID
            </th>
            <th scope="col">User</th>
            {header("cpu", "CPU")}
            {header("memory", "Memory")}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.pid}>
              <td>{row.name}</td>
              <td className="num muted">{row.pid}</td>
              <td className="muted">{row.user ?? "–"}</td>
              <td className="num">{row.cpu.toFixed(1)}%</td>
              <td className="num">{formatBytes(row.memory)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

export default function Performance() {
  const { snapshot, history, error } = usePerformance();
  const [selected, setSelected] = useState("cpu");
  const [minutes, setMinutes] = useState(5);
  const tabRefs = useRef({});
  const windowMs = minutes * 60 * 1000;
  const latest = history.at(-1);
  const list = resources(snapshot, latest);
  const active = list.find((r) => r.id === selected);

  function onTabKey(event, index) {
    const moves = { ArrowDown: index + 1, ArrowRight: index + 1, ArrowUp: index - 1, ArrowLeft: index - 1, Home: 0, End: list.length - 1 };
    if (!(event.key in moves)) return;
    event.preventDefault();
    const next = list[(moves[event.key] + list.length) % list.length];
    setSelected(next.id);
    tabRefs.current[next.id]?.focus();
  }

  return (
    <div className="page performance">
      <div className="page__header">
        <h1>Performance</h1>
        {snapshot && (
          <p className="muted">
            {snapshot.info.hostname}, {snapshot.info.os}. Sampled every {snapshot.interval_seconds} seconds.
          </p>
        )}
        <fieldset className="segmented performance__window" aria-label="Show the last">
          <legend className="visually-hidden">Show the last</legend>
          {WINDOWS.map((option) => (
            <label key={option.id} className="segmented__option">
              <input type="radio" name="perf-window" checked={minutes === option.id} onChange={() => setMinutes(option.id)} />
              <span>{option.label}</span>
            </label>
          ))}
        </fieldset>
      </div>

      {error && (
        <p className="notice notice--error" role="alert">
          Live data paused: {error.message}
        </p>
      )}

      <div className={`perf${error ? " is-refreshing" : ""}`}>
        <div className="perf__list" role="tablist" aria-label="Resources" aria-orientation="vertical">
          {list.map((resource, index) => (
            <button
              key={resource.id}
              ref={(element) => {
                tabRefs.current[resource.id] = element;
              }}
              type="button"
              role="tab"
              id={`tab-${resource.id}`}
              aria-selected={selected === resource.id}
              aria-controls="perf-panel"
              tabIndex={selected === resource.id ? 0 : -1}
              className="perf__tab"
              onClick={() => setSelected(resource.id)}
              onKeyDown={(event) => onTabKey(event, index)}
            >
              <span className="perf__tab-text">
                <span className="perf__tab-label">{resource.label}</span>
                <span className="perf__tab-value">{resource.value}</span>
                {resource.detail && <span className="perf__tab-detail">{resource.detail}</span>}
              </span>
              <LineChart
                title={resource.label}
                series={resource.series}
                points={history}
                windowMs={60 * 1000}
                max={resource.max}
                height={36}
                sparkline
              />
            </button>
          ))}
        </div>

        <section className="perf__panel" id="perf-panel" role="tabpanel" aria-labelledby={`tab-${selected}`}>
          <div className="perf__panel-head">
            <h2>{active.label}</h2>
            <span className="perf__panel-value">{active.value}</span>
          </div>
          <LineChart
            title={`${active.label} over the last ${minutes} ${minutes === 1 ? "minute" : "minutes"}`}
            series={active.series}
            points={history}
            windowMs={windowMs}
            max={active.max}
            formatValue={active.format}
            height={240}
          />
          <Details resource={selected} snapshot={snapshot} latest={latest} />
          {selected === "cpu" && snapshot && (
            <CoreGrid history={history} windowMs={windowMs} cores={latest?.cores.length ?? snapshot.info.cores_logical} />
          )}
        </section>
      </div>

      {snapshot && <Processes processes={snapshot.processes} />}
    </div>
  );
}
