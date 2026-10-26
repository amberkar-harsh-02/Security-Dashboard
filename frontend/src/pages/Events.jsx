import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { RefreshCw, X } from "lucide-react";
import { api } from "../api/client";
import EventTable from "../components/EventTable";
import SeverityBadge from "../components/SeverityBadge";
import { useApi } from "../hooks/useApi";
import { PRESETS, useTimeRange } from "../hooks/useTimeRange";
import { formatClock, formatDateMinute, formatNumber, SEVERITIES } from "../lib/format";
import "./Events.css";

const PAGE_SIZE = 100;
const TEXT_FIELDS = [
  { key: "ip", label: "Address", placeholder: "Source or destination IP" },
  { key: "user", label: "Account", placeholder: "Username" },
  { key: "host", label: "Host", placeholder: "Host name" },
];
const FILTER_LABELS = {
  q: "Text",
  ip: "Address",
  user: "Account",
  host: "Host",
  source: "Source",
  outcome: "Outcome",
  category: "Category",
  action: "Action",
  severity: "Severity",
};
const FILTER_KEYS = Object.keys(FILTER_LABELS);

function readFilters(params) {
  return Object.fromEntries(FILTER_KEYS.map((key) => [key, params.get(key) ?? ""]));
}

export default function Events() {
  const [params, setParams] = useSearchParams();
  const filters = readFilters(params);
  const page = Math.max(1, Number(params.get("page")) || 1);
  const range = useTimeRange();
  const [draft, setDraft] = useState(filters);
  const [sources, setSources] = useState([]);
  const queryKey = params.toString();
  const boundsKey = range.custom ? `${range.bounds().from}|${range.bounds().to}` : range.preset;

  // Keep the form in step with the URL (back button, pivot links).
  useEffect(() => setDraft(readFilters(new URLSearchParams(queryKey))), [queryKey]);

  useEffect(() => {
    api
      .get("/sources")
      .then((data) => setSources([...new Set(data.sources.map((s) => s.source))].sort()))
      .catch(() => {});
  }, []);

  const result = useApi(
    (signal) =>
      api.get(
        "/events",
        { ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)), limit: PAGE_SIZE, page, ...range.bounds() },
        { signal },
      ),
    [queryKey, boundsKey],
  );
  const [loadedAt, setLoadedAt] = useState(null);
  useEffect(() => {
    if (result.data) setLoadedAt(new Date());
  }, [result.data]);

  function apply(changes) {
    setParams((current) => {
      const next = new URLSearchParams(current);
      for (const [key, value] of Object.entries(changes)) {
        const text = String(value ?? "").trim();
        if (text) next.set(key, text);
        else next.delete(key);
      }
      if (!("page" in changes) || changes.page === 1) next.delete("page");
      return next;
    });
  }

  function clearAll() {
    apply(Object.fromEntries(FILTER_KEYS.map((key) => [key, ""])));
  }

  const severities = filters.severity.split(",").filter(Boolean);
  function toggleSeverity(severity) {
    const next = severities.includes(severity) ? severities.filter((s) => s !== severity) : [...severities, severity];
    apply({ severity: SEVERITIES.filter((s) => next.includes(s)).join(",") });
  }

  // Pivot links from expanded rows keep the current filters and add one more.
  const linkFor = useMemo(
    () => (filter) => {
      const next = new URLSearchParams(queryKey);
      next.delete("page");
      for (const [key, value] of Object.entries(filter)) next.set(key, String(value));
      return `/events?${next}`;
    },
    [queryKey],
  );

  const active = FILTER_KEYS.filter((key) => filters[key]);
  const total = result.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const preset = PRESETS.find((p) => p.id === range.preset);

  return (
    <div className="page events">
      <div className="page__header">
        <h1>Events</h1>
        <p className="muted">
          {range.custom
            ? `Between ${formatDateMinute(range.bounds().from)} and ${formatDateMinute(range.bounds().to)}`
            : `Last ${preset.label}`}
        </p>
      </div>

      <form
        className="event-search"
        role="search"
        onSubmit={(event) => {
          event.preventDefault();
          apply({ q: draft.q, ip: draft.ip, user: draft.user, host: draft.host });
        }}
      >
        <div className="event-search__main">
          <label htmlFor="event-q" className="visually-hidden">
            Text in the message or raw log line
          </label>
          <input
            id="event-q"
            className="input event-search__q"
            type="search"
            placeholder="Words in the message or raw log line, e.g. failed password"
            value={draft.q}
            onChange={(event) => setDraft({ ...draft, q: event.target.value })}
          />
          <button type="submit" className="button button--primary">
            Search
          </button>
        </div>

        <div className="filters event-search__fields">
          {TEXT_FIELDS.map((field) => (
            <label key={field.key} className="event-search__field">
              <span>{field.label}</span>
              <input
                className="input"
                placeholder={field.placeholder}
                value={draft[field.key]}
                onChange={(event) => setDraft({ ...draft, [field.key]: event.target.value })}
              />
            </label>
          ))}
          <label className="event-search__field">
            <span>Source</span>
            <select className="input" value={filters.source} onChange={(event) => apply({ source: event.target.value })}>
              <option value="">Any source</option>
              {sources.map((source) => (
                <option key={source} value={source}>
                  {source}
                </option>
              ))}
            </select>
          </label>
          <label className="event-search__field">
            <span>Outcome</span>
            <select className="input" value={filters.outcome} onChange={(event) => apply({ outcome: event.target.value })}>
              <option value="">Any outcome</option>
              <option value="failure">Failure</option>
              <option value="success">Success</option>
              <option value="unknown">Unknown</option>
            </select>
          </label>
          <div className="chips" role="group" aria-label="Severity">
            {SEVERITIES.map((severity) => (
              <button
                key={severity}
                type="button"
                className="chip"
                aria-pressed={severities.includes(severity)}
                onClick={() => toggleSeverity(severity)}
              >
                <SeverityBadge severity={severity} />
              </button>
            ))}
          </div>
        </div>
      </form>

      {active.length > 0 && (
        <ul className="tokens" aria-label="Active filters">
          {active.map((key) => (
            <li key={key} className="token">
              <span className="token__label">{FILTER_LABELS[key]}</span>
              <span className="token__value">{filters[key]}</span>
              <button
                type="button"
                className="token__remove"
                aria-label={`Remove ${FILTER_LABELS[key].toLowerCase()} filter`}
                onClick={() => apply({ [key]: "" })}
              >
                <X size={14} aria-hidden="true" />
              </button>
            </li>
          ))}
          <li>
            <button type="button" className="button button--quiet" onClick={clearAll}>
              Clear all
            </button>
          </li>
        </ul>
      )}

      <div className="results__head">
        <p role="status">
          {result.data ? (
            <>
              <strong>{formatNumber(total)}</strong> {total === 1 ? "event" : "events"}
              {total > PAGE_SIZE && `, showing ${formatNumber((page - 1) * PAGE_SIZE + 1)} to ${formatNumber(Math.min(page * PAGE_SIZE, total))}`}
            </>
          ) : (
            "Searching"
          )}
        </p>
        <div className="results__actions">
          {loadedAt && <span className="muted">Updated {formatClock(loadedAt)}</span>}
          <button type="button" className="button" onClick={result.reload} disabled={result.loading}>
            <RefreshCw size={14} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {result.error && (
        <p className="notice notice--error" role="alert">
          {result.error.message}
        </p>
      )}

      {result.data && total === 0 && (
        <p className="empty">No events match. Widen the time range in the top bar or remove a filter.</p>
      )}

      {result.data?.events.length > 0 && (
        <div className={result.loading ? "is-refreshing" : undefined}>
          <EventTable events={result.data.events} showSeverity showSource linkFor={linkFor} />
          {pages > 1 && (
            <nav className="pager results__pager" aria-label="Pages">
              <button type="button" className="button" disabled={page <= 1} onClick={() => apply({ page: page - 1 })}>
                Previous
              </button>
              <span>
                Page {page} of {formatNumber(pages)}
              </span>
              <button type="button" className="button" disabled={page >= pages} onClick={() => apply({ page: page + 1 })}>
                Next
              </button>
            </nav>
          )}
        </div>
      )}
    </div>
  );
}
