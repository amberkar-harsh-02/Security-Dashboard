import { useState } from "react";
import { Link, useLocation, useParams } from "react-router";
import { ArrowLeft, ExternalLink, ShieldBan } from "lucide-react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import EventTable from "../components/EventTable";
import SeverityBadge from "../components/SeverityBadge";
import StatusLabel, { STATUSES } from "../components/StatusLabel";
import { useApi } from "../hooks/useApi";
import { useAlertFeed } from "../hooks/useLive";
import { useUsers } from "../hooks/useLookups";
import { BLOCK_DURATIONS, formatTimeLeft, fromValue, toValue } from "../lib/blocks";
import { formatDateTime, formatNumber, formatRelative } from "../lib/format";
import { describeTrigger, FIELD_LABELS, mitreUrl } from "../lib/rules";
import "./AlertDetail.css";

// Event search understands these filters; other group fields link to a text search.
const EVENT_FILTERS = { src_ip: "ip", dst_ip: "ip", user: "user", host: "host" };

function eventSearchLink(field, value) {
  const key = EVENT_FILTERS[field];
  return key ? `/events?${new URLSearchParams({ [key]: value })}` : `/events?${new URLSearchParams({ q: String(value) })}`;
}

/** Block the alert's source address at the server firewall, or show and end an existing block. */
function SourceBlock({ alert, onChanged }) {
  const ip = alert.group_fields.src_ip;
  const [minutes, setMinutes] = useState("60");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  if (!ip) return null;

  async function run(action) {
    setBusy(true);
    setError(null);
    try {
      await action();
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const blocked = alert.blocked;
  return (
    <div className="source-block">
      {blocked ? (
        <p className="source-block__state">
          <ShieldBan size={16} aria-hidden="true" />
          <span>
            <strong className="mono">{ip}</strong> is blocked
            {blocked.expires_at ? ` until ${formatDateTime(blocked.expires_at)} (${formatTimeLeft(blocked.expires_at)})` : " permanently"}.
          </span>
          <button
            type="button"
            className="button"
            disabled={busy}
            onClick={() => run(() => api.post(`/blocks/${blocked.id}/unblock`))}
          >
            Unblock
          </button>
        </p>
      ) : (
        <div className="source-block__form">
          <label>
            <span>
              Block <span className="mono">{ip}</span> for
            </span>
            <select className="input" value={minutes} disabled={busy} onChange={(e) => setMinutes(e.target.value)}>
              {BLOCK_DURATIONS.map((d) => (
                <option key={d.label} value={toValue(d.minutes)}>
                  {d.label.toLowerCase()}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="button"
            disabled={busy}
            onClick={() =>
              run(() => api.post("/blocks", { ip, minutes: fromValue(minutes), reason: alert.title, alert_id: alert.id }))
            }
          >
            <ShieldBan size={14} aria-hidden="true" />
            Block
          </button>
        </div>
      )}
      {error && (
        <p className="source-block__error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

function Controls({ alert, onChange, busy }) {
  const users = useUsers();
  const { user } = useAuth();
  return (
    <div className="detail__controls">
      <fieldset className="segmented" aria-label="Status">
        <legend className="visually-hidden">Status</legend>
        {STATUSES.map((status) => (
          <label key={status.id} className="segmented__option">
            <input
              type="radio"
              name="detail-status"
              checked={alert.status === status.id}
              disabled={busy}
              onChange={() => onChange({ status: status.id })}
            />
            <span>{status.label}</span>
          </label>
        ))}
      </fieldset>

      <label className="detail__assignee">
        <span>Assignee</span>
        <select
          className="input"
          value={alert.assignee ?? ""}
          disabled={busy}
          onChange={(event) => onChange({ assignee: event.target.value || null })}
        >
          <option value="">Unassigned</option>
          {users.map((name) => (
            <option key={name} value={name}>
              {name === user ? `${name} (you)` : name}
            </option>
          ))}
        </select>
      </label>
      {alert.assignee !== user && (
        <button type="button" className="button" disabled={busy} onClick={() => onChange({ assignee: user })}>
          Assign to me
        </button>
      )}
    </div>
  );
}

function Activity({ alert, onNote }) {
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const entries = [{ id: "created", kind: "created", created_at: alert.created_at }, ...alert.notes];

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onNote(body);
      setBody("");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="section detail__activity" aria-labelledby="activity-heading">
      <div className="section__head">
        <h2 id="activity-heading">Activity</h2>
      </div>
      <ol className="activity">
        {entries.map((entry) => (
          <li key={entry.id} className={`activity__item activity__item--${entry.kind}`}>
            <div className="activity__meta">
              <span className="activity__who">{entry.kind === "created" ? "Detection engine" : entry.author}</span>
              <time dateTime={entry.created_at} title={formatDateTime(entry.created_at)}>
                {formatRelative(entry.created_at)}
              </time>
            </div>
            <p className="activity__body">{entry.kind === "created" ? `Raised this alert from rule “${alert.rule_name}”.` : entry.body}</p>
          </li>
        ))}
      </ol>

      <form className="note-form" onSubmit={submit}>
        <label htmlFor="note-body">Add a note</label>
        <textarea
          id="note-body"
          className="input"
          rows={3}
          maxLength={4000}
          placeholder="What you checked, what you found, what happens next"
          value={body}
          onChange={(event) => setBody(event.target.value)}
        />
        {error && (
          <p className="note-form__error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" className="button button--primary" disabled={busy || !body.trim()}>
          {busy ? "Adding…" : "Add note"}
        </button>
      </form>
    </section>
  );
}

export default function AlertDetail() {
  const { id } = useParams();
  const location = useLocation();
  const backTo = location.state?.from || "/alerts";
  const [alert, setAlert] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const loaded = useApi(
    (signal) =>
      api.get(`/alerts/${id}`, undefined, { signal }).then((data) => {
        setAlert(data);
        return data;
      }),
    [id],
  );

  useAlertFeed(({ alert: changed }) => {
    if (String(changed.id) === id) loaded.reload();
  });

  async function change(changes) {
    setBusy(true);
    setError(null);
    try {
      setAlert(await api.patch(`/alerts/${id}`, changes));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function addNote(body) {
    await api.post(`/alerts/${id}/notes`, { body });
    loaded.reload();
  }

  if (loaded.error && !alert) {
    return (
      <div className="page">
        <Link className="detail__back" to={backTo}>
          <ArrowLeft size={16} aria-hidden="true" /> Alerts
        </Link>
        <p className="notice notice--error" role="alert">
          {loaded.error.status === 404 ? `Alert ${id} does not exist. It may have been removed.` : loaded.error.message}
        </p>
      </div>
    );
  }
  if (!alert) return <div className="page" aria-busy="true" />;

  const groupEntries = Object.entries(alert.group_fields);
  const truncated = alert.event_count > alert.events.length;

  return (
    <div className="page detail">
      <Link className="detail__back" to={backTo}>
        <ArrowLeft size={16} aria-hidden="true" /> Alerts
      </Link>

      <header className="detail__header">
        <SeverityBadge severity={alert.severity} />
        <h1>{alert.title}</h1>
      </header>

      <dl className="detail__facts">
        <div>
          <dt>Status</dt>
          <dd>
            <StatusLabel status={alert.status} />
          </dd>
        </div>
        <div>
          <dt>Assignee</dt>
          <dd className={alert.assignee ? undefined : "muted"}>{alert.assignee ?? "Unassigned"}</dd>
        </div>
        <div>
          <dt>First seen</dt>
          <dd>{formatDateTime(alert.first_seen)}</dd>
        </div>
        <div>
          <dt>Last activity</dt>
          <dd>{formatDateTime(alert.last_seen)}</dd>
        </div>
        <div>
          <dt>Events</dt>
          <dd>{formatNumber(alert.event_count)}</dd>
        </div>
        {alert.mitre_technique && (
          <div>
            <dt>MITRE ATT&amp;CK</dt>
            <dd>
              <a href={mitreUrl(alert.mitre_technique)} target="_blank" rel="noopener noreferrer">
                {alert.mitre_technique} {alert.mitre_name}
                <ExternalLink size={12} aria-label="(opens in a new tab)" />
              </a>
              <span className="muted"> {alert.mitre_tactic}</span>
            </dd>
          </div>
        )}
      </dl>

      <Controls alert={alert} onChange={change} busy={busy} />
      {error && (
        <p className="notice notice--error" role="alert">
          {error}
        </p>
      )}

      <div className="detail__grid">
        <div className="detail__main">
          <section className="section" aria-labelledby="why-heading">
            <div className="section__head">
              <h2 id="why-heading">Why this alert fired</h2>
              <Link to={`/rules#${alert.rule_id}`}>{alert.rule_name}</Link>
            </div>
            {alert.rule ? (
              <>
                <p className="detail__description">{alert.rule.description}</p>
                <p className="detail__trigger">{describeTrigger(alert.rule)}</p>
              </>
            ) : (
              <p className="muted">The rule “{alert.rule_id}” is no longer loaded.</p>
            )}
            {groupEntries.length > 0 && (
              <dl className="fields detail__group">
                {groupEntries.map(([field, value]) => (
                  <div key={field}>
                    <dt>{FIELD_LABELS[field] ?? field}</dt>
                    <dd>
                      <Link className="mono" to={eventSearchLink(field, value)}>
                        {value}
                      </Link>
                    </dd>
                  </div>
                ))}
              </dl>
            )}
            <SourceBlock alert={alert} onChanged={loaded.reload} />
          </section>

          <section className="section" aria-labelledby="events-heading">
            <div className="section__head">
              <h2 id="events-heading">Events</h2>
              <span className="muted">
                {truncated
                  ? `First ${formatNumber(alert.events.length)} of ${formatNumber(alert.event_count)}`
                  : `${formatNumber(alert.events.length)} linked`}
              </span>
            </div>
            {alert.events.length ? (
              <EventTable events={alert.events} linkFor={(filter) => `/events?${new URLSearchParams(filter)}`} />
            ) : (
              <p className="empty">The events for this alert were removed by the retention policy.</p>
            )}
          </section>
        </div>

        <Activity alert={alert} onNote={addNote} />
      </div>
    </div>
  );
}
