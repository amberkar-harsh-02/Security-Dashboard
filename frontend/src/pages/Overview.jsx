import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router";
import { api } from "../api/client";
import AlertBand from "../components/AlertBand";
import HostHealth from "../components/HostHealth";
import SeverityBadge from "../components/SeverityBadge";
import { useApi } from "../hooks/useApi";
import { useAlertFeed, useLive } from "../hooks/useLive";
import { PRESETS, useTimeRange } from "../hooks/useTimeRange";
import { formatCompact, formatDateMinute, formatDateTime, formatNumber, formatRelative, SEVERITIES } from "../lib/format";
import "./Overview.css";

const REFRESH_MS = 30000;
const FRESH_MS = 4000;

function eventsLink(params) {
  return `/events?${new URLSearchParams(params)}`;
}

function useRefreshOnAlerts(reload) {
  const timer = useRef(null);
  useAlertFeed(() => {
    clearTimeout(timer.current);
    timer.current = setTimeout(reload, 1200);
  });
  useEffect(() => {
    const interval = setInterval(reload, REFRESH_MS);
    return () => {
      clearInterval(interval);
      clearTimeout(timer.current);
    };
  }, [reload]);
}

function WindowCaption() {
  const range = useTimeRange();
  const preset = PRESETS.find((p) => p.id === range.preset);
  if (!range.custom) return <p className="overview__window">Last {preset.label}</p>;
  const { from, to } = range.bounds();
  return (
    <p className="overview__window">
      Focused on {formatDateMinute(from)} to {formatDateMinute(to)}
      <button type="button" className="button button--quiet" onClick={range.clearWindow}>
        Show all of the last {preset.label}
      </button>
    </p>
  );
}

function OpenAlertsFigure({ overview }) {
  const counts = overview?.open_by_severity ?? {};
  const total = overview?.totals.open_alerts;
  return (
    <section className="figure figure--hero" aria-labelledby="open-alerts-label">
      <h2 id="open-alerts-label" className="figure__label">
        Open alerts
      </h2>
      <p className="figure__value">{total === undefined ? "–" : formatNumber(total)}</p>
      <ul className="figure__breakdown">
        {SEVERITIES.filter((s) => s !== "info").map((severity) => (
          <li key={severity}>
            <SeverityBadge severity={severity} />
            <span className="figure__count">{formatNumber(counts[severity] ?? 0)}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Figure({ label, value, note }) {
  return (
    <div className="figure">
      <p className="figure__label">{label}</p>
      <p className="figure__value figure__value--small">{value}</p>
      {note && <p className="figure__note">{note}</p>}
    </div>
  );
}

function AlertQueue({ alerts, fresh, total }) {
  const navigate = useNavigate();
  if (!alerts) return null;
  if (!alerts.length) {
    return <p className="empty">No open alerts in this period. New alerts appear here as soon as a rule fires.</p>;
  }
  return (
    <>
      <table className="table queue">
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Alert</th>
            <th scope="col" className="num queue__events">
              Events
            </th>
            <th scope="col">Last activity</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr
              key={alert.id}
              className={`table__row--link${fresh.has(alert.id) ? " table__row--fresh" : ""}`}
              onClick={(event) => {
                if (event.target.closest("a")) return;
                navigate(`/alerts/${alert.id}`);
              }}
            >
              <td>
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="queue__title">
                <Link to={`/alerts/${alert.id}`}>{alert.title}</Link>
                <span className="queue__rule">{alert.rule_name}</span>
              </td>
              <td className="num queue__events">{formatNumber(alert.event_count)}</td>
              <td title={formatDateTime(alert.last_seen)}>{formatRelative(alert.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {total > alerts.length && (
        <p className="section__more">
          <Link to="/alerts?status=open">See all {formatNumber(total)} open alerts</Link>
        </p>
      )}
    </>
  );
}

function TopSources({ rows }) {
  if (!rows.length) return <p className="empty">No source addresses in this period.</p>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th scope="col">Address</th>
          <th scope="col" className="num">
            Events
          </th>
          <th scope="col" className="num">
            Failures
          </th>
          <th scope="col" className="num">
            Alerts
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.src_ip}>
            <td>
              <Link className="mono" to={eventsLink({ ip: row.src_ip })}>
                {row.src_ip}
              </Link>
            </td>
            <td className="num">{formatCompact(row.events)}</td>
            <td className="num">{formatCompact(row.failures)}</td>
            <td className={`num${row.alerts ? " num--strong" : " muted"}`}>{row.alerts}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TopRules({ rows }) {
  if (!rows.length) return <p className="empty">No rules fired in this period.</p>;
  const max = Math.max(...rows.map((r) => r.alerts));
  return (
    <ul className="bars">
      {rows.map((row) => (
        <li key={row.rule_id} className="bars__row">
          <Link className="bars__name" to={`/alerts?rule_id=${encodeURIComponent(row.rule_id)}`}>
            {row.rule_name}
          </Link>
          <span className="bars__track" aria-hidden="true">
            <span className="bars__fill" style={{ width: `${(row.alerts / max) * 100}%` }} />
          </span>
          <span className="bars__value">{formatNumber(row.alerts)}</span>
        </li>
      ))}
    </ul>
  );
}

function FailedLogins({ rows }) {
  if (!rows.length) return <p className="empty">No failed logins in this period.</p>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th scope="col">Account</th>
          <th scope="col" className="num">
            Failures
          </th>
          <th scope="col" className="num">
            From addresses
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.user}>
            <td>
              <Link className="mono" to={eventsLink({ user: row.user, outcome: "failure" })}>
                {row.user}
              </Link>
            </td>
            <td className="num">{formatNumber(row.failures)}</td>
            <td className="num">{formatNumber(row.addresses)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Overview() {
  const range = useTimeRange();
  const { stats } = useLive();
  const [fresh, setFresh] = useState(() => new Set());
  const windowKey = range.custom ? `${range.bounds().from}|${range.bounds().to}` : range.preset;

  const overview = useApi(
    (signal) => {
      const window = range.custom ? range.bounds() : {};
      return api.get("/stats/overview", { range: range.preset, ...window }, { signal });
    },
    [windowKey],
  );

  const queue = useApi(
    (signal) => api.get("/alerts", { status: "open", sort: "severity", limit: 8, ...range.bounds() }, { signal }),
    [windowKey],
  );

  const { reload: reloadOverview } = overview;
  const { reload: reloadQueue } = queue;
  const reload = useCallback(() => {
    reloadOverview();
    reloadQueue();
  }, [reloadOverview, reloadQueue]);
  useRefreshOnAlerts(reload);

  useAlertFeed(({ created, alert }) => {
    if (!created) return;
    setFresh((current) => new Set(current).add(alert.id));
    setTimeout(() => {
      setFresh((current) => {
        const next = new Set(current);
        next.delete(alert.id);
        return next;
      });
    }, FRESH_MS);
  });

  const data = overview.data;
  const error = overview.error || queue.error;

  return (
    <div className="page overview">
      <div className="page__header">
        <h1>Overview</h1>
        <WindowCaption />
      </div>

      {error && (
        <p className="notice notice--error" role="alert">
          {error.message}
        </p>
      )}

      {data && (
        <AlertBand
          series={data.alert_series}
          events={data.event_series}
          bucketSeconds={data.bucket_seconds}
          selection={range.custom ? range.bounds() : null}
          onSelect={range.setWindow}
          onClear={range.clearWindow}
          dimmed={overview.loading}
        />
      )}

      <div className={`overview__figures${overview.loading && data ? " is-refreshing" : ""}`}>
        <OpenAlertsFigure overview={data} />
        <Figure label="Alerts raised" value={data ? formatNumber(data.totals.alerts) : "–"} note="in this period" />
        <Figure label="Events stored" value={data ? formatCompact(data.totals.events) : "–"} note="in this period" />
        <Figure
          label="Event rate"
          value={stats.events_last_minute === null ? "–" : formatNumber(stats.events_last_minute)}
          note="events in the last minute"
        />
      </div>

      <div className={`overview__grid${overview.loading && data ? " is-refreshing" : ""}`}>
        <div className="overview__main">
          <section className="section overview__queue" aria-labelledby="queue-heading">
            <div className="section__head">
              <h2 id="queue-heading">Open alerts, most severe first</h2>
            </div>
            <AlertQueue alerts={queue.data?.alerts} total={queue.data?.total ?? 0} fresh={fresh} />
          </section>

          <section className="section" aria-labelledby="rules-heading">
            <div className="section__head">
              <h2 id="rules-heading">Rules that fired</h2>
            </div>
            {data && <TopRules rows={data.top_rules} />}
          </section>
        </div>

        <div className="overview__side">
          <section className="section" aria-labelledby="sources-heading">
            <div className="section__head">
              <h2 id="sources-heading">Top source addresses</h2>
            </div>
            {data && <TopSources rows={data.top_sources} />}
          </section>

          <section className="section" aria-labelledby="logins-heading">
            <div className="section__head">
              <h2 id="logins-heading">Accounts with failed logins</h2>
            </div>
            {data && <FailedLogins rows={data.top_failed_users} />}
          </section>

          <section className="section" aria-labelledby="health-heading">
            <div className="section__head">
              <h2 id="health-heading">SIEM host</h2>
            </div>
            <HostHealth />
          </section>
        </div>
      </div>
    </div>
  );
}
