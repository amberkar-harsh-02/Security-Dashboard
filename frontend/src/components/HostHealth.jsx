import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../api/client";
import "./HostHealth.css";

// CPU, memory and disk of the machine running the backend, refreshed every 10 s.
// The Performance page has the full live view.

const METRICS = [
  { key: "cpu", label: "CPU" },
  { key: "memory", label: "Memory" },
  { key: "disk", label: "Disk" },
];

function level(value) {
  if (value >= 90) return "danger";
  if (value >= 75) return "warning";
  return "normal";
}

export default function HostHealth() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      api
        .get("/system-health")
        .then((data) => {
          if (!cancelled) {
            setHealth(data);
            setError(null);
          }
        })
        .catch((err) => !cancelled && setError(err.message));
    load();
    const timer = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  if (error) return <p className="muted">{error}</p>;

  return (
    <>
      <dl className="health">
        {METRICS.map(({ key, label }) => {
          const value = health?.[key];
          const state = value === undefined ? "normal" : level(value);
          return (
            <div key={key} className={`health__row health__row--${state}`}>
              <dt>{label}</dt>
              <dd>
                <span
                  className="health__meter"
                  role="meter"
                  aria-label={`${label} usage`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={value ?? 0}
                >
                  <span className="health__fill" style={{ width: `${value ?? 0}%` }} />
                </span>
                <span className="health__value">{value === undefined ? "–" : `${Math.round(value)}%`}</span>
              </dd>
            </div>
          );
        })}
      </dl>
      <p className="health__more">
        <Link to="/performance">Open Performance</Link> for live graphs and top processes.
      </p>
    </>
  );
}
