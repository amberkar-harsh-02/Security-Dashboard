import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import SeverityBadge from "../components/SeverityBadge";
import StatusLabel, { STATUSES } from "../components/StatusLabel";
import { useApi } from "../hooks/useApi";
import { useAlertFeed } from "../hooks/useLive";
import { useRules, useUsers } from "../hooks/useLookups";
import { PRESETS, useTimeRange } from "../hooks/useTimeRange";
import { formatDateMinute, formatDateTime, formatNumber, formatRelative, SEVERITIES } from "../lib/format";
import "./Alerts.css";

const PAGE_SIZE = 50;
const SORTS = [
  { id: "recent", label: "Latest activity" },
  { id: "severity", label: "Most severe" },
  { id: "oldest", label: "Oldest first" },
];

/** Filters live in the URL so a filtered list can be bookmarked and shared. */
function useFilters() {
  const [params, setParams] = useSearchParams();
  const filters = {
    status: params.get("status") ?? "open",
    severity: (params.get("severity") ?? "").split(",").filter(Boolean),
    rule_id: params.get("rule_id") ?? "",
    assignee: params.get("assignee") ?? "",
    q: params.get("q") ?? "",
    sort: params.get("sort") ?? "recent",
    page: Math.max(1, Number(params.get("page")) || 1),
  };

  const update = useCallback(
    (changes) => {
      setParams(
        (current) => {
          const next = new URLSearchParams(current);
          for (const [key, value] of Object.entries(changes)) {
            const text = Array.isArray(value) ? value.join(",") : String(value ?? "");
            if (text === "" || (key === "status" && text === "open") || (key === "sort" && text === "recent")) {
              next.delete(key);
            } else {
              next.set(key, text);
            }
          }
          // Any filter change returns to the first page.
          if (!("page" in changes)) next.delete("page");
          if (changes.page === 1) next.delete("page");
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  return [filters, update, params.toString()];
}

function apiParams(filters, bounds) {
  return {
    status: filters.status === "all" ? undefined : filters.status,
    severity: filters.severity,
    rule_id: filters.rule_id || undefined,
    // "none" in the URL means unassigned, which the API spells as an empty assignee.
    assignee: filters.assignee === "none" ? "" : filters.assignee || undefined,
    q: filters.q || undefined,
    sort: filters.sort,
    limit: PAGE_SIZE,
    page: filters.page,
    ...bounds,
  };
}

function FilterBar({ filters, update }) {
  const rules = useRules();
  const users = useUsers();
  const { user } = useAuth();
  const [text, setText] = useState(filters.q);

  useEffect(() => setText(filters.q), [filters.q]);

  function toggleSeverity(severity) {
    const next = filters.severity.includes(severity)
      ? filters.severity.filter((s) => s !== severity)
      : [...filters.severity, severity];
    update({ severity: SEVERITIES.filter((s) => next.includes(s)) });
  }

  return (
    <div className="filters" role="group" aria-label="Filter alerts">
      <fieldset className="segmented" aria-label="Status">
        <legend className="visually-hidden">Status</legend>
        {[...STATUSES, { id: "all", label: "All" }].map((option) => (
          <label key={option.id} className="segmented__option">
            <input
              type="radio"
              name="alert-status"
              checked={filters.status === option.id}
              onChange={() => update({ status: option.id })}
            />
            <span>{option.label}</span>
          </label>
        ))}
      </fieldset>

      <div className="chips" role="group" aria-label="Severity">
        {SEVERITIES.filter((s) => s !== "info").map((severity) => (
          <button
            key={severity}
            type="button"
            className="chip"
            aria-pressed={filters.severity.includes(severity)}
            onClick={() => toggleSeverity(severity)}
          >
            <SeverityBadge severity={severity} />
          </button>
        ))}
      </div>

      <label className="filters__field">
        <span className="visually-hidden">Rule</span>
        <select className="input" value={filters.rule_id} onChange={(event) => update({ rule_id: event.target.value })}>
          <option value="">All rules</option>
          {rules.map((rule) => (
            <option key={rule.id} value={rule.id}>
              {rule.name}
            </option>
          ))}
        </select>
      </label>

      <label className="filters__field">
        <span className="visually-hidden">Assignee</span>
        <select className="input" value={filters.assignee} onChange={(event) => update({ assignee: event.target.value })}>
          <option value="">Anyone</option>
          <option value="none">Unassigned</option>
          {user && <option value={user}>Assigned to me</option>}
          {users
            .filter((name) => name !== user)
            .map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
        </select>
      </label>

      <form
        className="filters__search"
        role="search"
        onSubmit={(event) => {
          event.preventDefault();
          update({ q: text.trim() });
        }}
      >
        <label htmlFor="alert-search" className="visually-hidden">
          Search alert titles
        </label>
        <input
          id="alert-search"
          className="input"
          type="search"
          placeholder="Title or address"
          value={text}
          onChange={(event) => setText(event.target.value)}
          onBlur={() => text.trim() !== filters.q && update({ q: text.trim() })}
        />
      </form>

      <label className="filters__field filters__sort">
        <span>Sort</span>
        <select className="input" value={filters.sort} onChange={(event) => update({ sort: event.target.value })}>
          {SORTS.map((sort) => (
            <option key={sort.id} value={sort.id}>
              {sort.label}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}

function BulkBar({ selected, onApply, onClear, busy }) {
  if (!selected.size) return null;
  return (
    <div className="bulk" role="region" aria-label="Selected alerts">
      <span className="bulk__count">{selected.size} selected</span>
      <button type="button" className="button" disabled={busy} onClick={() => onApply("acknowledged")}>
        Acknowledge
      </button>
      <button type="button" className="button" disabled={busy} onClick={() => onApply("closed")}>
        Close
      </button>
      <button type="button" className="button" disabled={busy} onClick={() => onApply("open")}>
        Reopen
      </button>
      <button type="button" className="button button--quiet" onClick={onClear}>
        Clear selection
      </button>
    </div>
  );
}

function Pagination({ page, total, onPage }) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (pages === 1) return null;
  return (
    <nav className="pager" aria-label="Pages">
      <button type="button" className="button" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        Previous
      </button>
      <span>
        Page {page} of {pages}
      </span>
      <button type="button" className="button" disabled={page >= pages} onClick={() => onPage(page + 1)}>
        Next
      </button>
    </nav>
  );
}

export default function Alerts() {
  const [filters, update, queryKey] = useFilters();
  const range = useTimeRange();
  const navigate = useNavigate();
  const location = useLocation();
  const [selected, setSelected] = useState(() => new Set());
  const [cursor, setCursor] = useState(0);
  const [fresh, setFresh] = useState(() => new Set());
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const rowRefs = useRef([]);
  const boundsKey = range.custom ? `${range.bounds().from}|${range.bounds().to}` : range.preset;

  const list = useApi((signal) => api.get("/alerts", apiParams(filters, range.bounds()), { signal }), [queryKey, boundsKey]);
  const alerts = useMemo(() => list.data?.alerts ?? [], [list.data]);

  // A new filter or page starts a new selection.
  useEffect(() => {
    setSelected(new Set());
    setCursor(0);
  }, [queryKey, boundsKey]);

  const reloadTimer = useRef(null);
  useAlertFeed(({ created, alert }) => {
    clearTimeout(reloadTimer.current);
    reloadTimer.current = setTimeout(list.reload, 800);
    if (created) {
      setFresh((current) => new Set(current).add(alert.id));
      setTimeout(() => setFresh((current) => {
        const next = new Set(current);
        next.delete(alert.id);
        return next;
      }), 4000);
    }
  });
  useEffect(() => () => clearTimeout(reloadTimer.current), []);

  function toggle(id) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    setSelected((current) => (current.size === alerts.length ? new Set() : new Set(alerts.map((a) => a.id))));
  }

  async function applyStatus(status) {
    setBusy(true);
    setMessage(null);
    try {
      const result = await api.post("/alerts/bulk", { ids: [...selected], status });
      const label = STATUSES.find((s) => s.id === status).label.toLowerCase();
      setMessage(`${result.changed.length} ${result.changed.length === 1 ? "alert" : "alerts"} marked ${label}.`);
      setSelected(new Set());
      list.reload();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  function open(alert) {
    navigate(`/alerts/${alert.id}`, { state: { from: location.pathname + location.search } });
  }

  function focusRow(index) {
    const bounded = Math.max(0, Math.min(alerts.length - 1, index));
    setCursor(bounded);
    rowRefs.current[bounded]?.focus();
  }

  function onRowKeyDown(event, alert, index) {
    if (event.target.closest("input, button, select, a") && event.key !== "Enter") return;
    if (event.key === "j" || event.key === "ArrowDown") {
      event.preventDefault();
      focusRow(index + 1);
    } else if (event.key === "k" || event.key === "ArrowUp") {
      event.preventDefault();
      focusRow(index - 1);
    } else if (event.key === "x" || event.key === " ") {
      event.preventDefault();
      toggle(alert.id);
    } else if (event.key === "Enter" && !event.target.closest("a")) {
      event.preventDefault();
      open(alert);
    }
  }

  const preset = PRESETS.find((p) => p.id === range.preset);
  const total = list.data?.total ?? 0;
  const allSelected = alerts.length > 0 && selected.size === alerts.length;

  return (
    <div className="page alerts">
      <div className="page__header">
        <h1>Alerts</h1>
        <p className="muted">
          {list.data ? `${formatNumber(total)} ${total === 1 ? "alert" : "alerts"}` : "Loading"} with activity{" "}
          {range.custom
            ? `between ${formatDateMinute(range.bounds().from)} and ${formatDateMinute(range.bounds().to)}`
            : `in the last ${preset.label}`}
        </p>
      </div>

      <FilterBar filters={filters} update={update} />

      <BulkBar selected={selected} onApply={applyStatus} onClear={() => setSelected(new Set())} busy={busy} />
      <p className="alerts__message" role="status">
        {message}
      </p>

      {list.error && (
        <p className="notice notice--error" role="alert">
          {list.error.message}
        </p>
      )}

      {list.data && !alerts.length && (
        <div className="empty">
          <p>No alerts match these filters.</p>
          <button type="button" className="button" onClick={() => update({ status: "all", severity: [], rule_id: "", assignee: "", q: "" })}>
            Show all alerts
          </button>
        </div>
      )}

      {alerts.length > 0 && (
        <div className={list.loading ? "is-refreshing" : undefined}>
          <table className="table alerts__table">
            <thead>
              <tr>
                <th scope="col" className="alerts__check">
                  <input type="checkbox" aria-label="Select all alerts on this page" checked={allSelected} onChange={toggleAll} />
                </th>
                <th scope="col">Severity</th>
                <th scope="col">Alert</th>
                <th scope="col">Status</th>
                <th scope="col">Assignee</th>
                <th scope="col" className="num">
                  Events
                </th>
                <th scope="col">Last activity</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, index) => (
                <tr
                  key={alert.id}
                  ref={(element) => {
                    rowRefs.current[index] = element;
                  }}
                  tabIndex={index === cursor ? 0 : -1}
                  className={[
                    "table__row--link",
                    selected.has(alert.id) && "is-selected",
                    fresh.has(alert.id) && "table__row--fresh",
                  ]
                    .filter(Boolean)
                    .join(" ")}
                  onFocus={() => setCursor(index)}
                  onKeyDown={(event) => onRowKeyDown(event, alert, index)}
                  onClick={(event) => {
                    if (event.target.closest("a, input, label")) return;
                    open(alert);
                  }}
                >
                  <td className="alerts__check">
                    <input
                      type="checkbox"
                      tabIndex={-1}
                      aria-label={`Select ${alert.title}`}
                      checked={selected.has(alert.id)}
                      onChange={() => toggle(alert.id)}
                    />
                  </td>
                  <td>
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="alerts__title">
                    <Link to={`/alerts/${alert.id}`} state={{ from: location.pathname + location.search }} tabIndex={-1}>
                      {alert.title}
                    </Link>
                    <span className="alerts__rule">{alert.rule_name}</span>
                  </td>
                  <td>
                    <StatusLabel status={alert.status} />
                  </td>
                  <td className={alert.assignee ? undefined : "muted"}>{alert.assignee ?? "Unassigned"}</td>
                  <td className="num">{formatNumber(alert.event_count)}</td>
                  <td title={formatDateTime(alert.last_seen)}>{formatRelative(alert.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="alerts__footer">
            <p className="alerts__keys">
              Keys: <kbd>j</kbd> and <kbd>k</kbd> move, <kbd>x</kbd> selects, <kbd>Enter</kbd> opens.
            </p>
            <Pagination page={filters.page} total={total} onPage={(page) => update({ page })} />
          </div>
        </div>
      )}
    </div>
  );
}
