import { Fragment, useState } from "react";
import { Link } from "react-router";
import { ChevronDown, ChevronRight } from "lucide-react";
import { formatDateTime } from "../lib/format";
import SeverityBadge from "./SeverityBadge";
import "./EventTable.css";

// Fields shown when a row is expanded, in this order.
const DETAIL_FIELDS = ["source", "category", "action", "outcome", "user", "src_ip", "src_port", "dst_ip", "dst_port", "host", "process", "severity"];

/** Event search filter for a field value, or null when the field has no filter. */
export function pivotFilter(field, value) {
  if (field === "src_ip" || field === "dst_ip") return { ip: value };
  if (["user", "host", "source", "outcome", "category", "action"].includes(field)) return { [field]: value };
  return null;
}

/**
 * Events with expandable rows showing every field and the raw log line.
 * `linkFor(filter)` turns a pivot filter into a link target; when given, field values
 * in the expanded view become links that narrow event search to that value.
 */
export default function EventTable({ events, showSeverity = false, showSource = false, linkFor }) {
  const [open, setOpen] = useState(() => new Set());
  const toggle = (id) =>
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const columns = 4 + Number(showSeverity) + Number(showSource);

  return (
    <table className="table events-table">
      <thead>
        <tr>
          <th scope="col" className="events-table__toggle">
            <span className="visually-hidden">Details</span>
          </th>
          <th scope="col">Time</th>
          {showSeverity && <th scope="col">Severity</th>}
          <th scope="col">Host</th>
          {showSource && <th scope="col">Source</th>}
          <th scope="col">Outcome</th>
          <th scope="col">Message</th>
        </tr>
      </thead>
      <tbody>
        {events.map((event) => {
          const expanded = open.has(event.id);
          return (
            <Fragment key={event.id}>
              <tr className={expanded ? "is-expanded" : undefined}>
                <td className="events-table__toggle">
                  <button
                    type="button"
                    className="button button--quiet"
                    aria-expanded={expanded}
                    aria-label={`${expanded ? "Hide" : "Show"} details for event ${event.id}`}
                    onClick={() => toggle(event.id)}
                  >
                    {expanded ? <ChevronDown size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
                  </button>
                </td>
                <td className="events-table__time">{formatDateTime(event.ts)}</td>
                {showSeverity && (
                  <td>
                    <SeverityBadge severity={event.severity} />
                  </td>
                )}
                <td className="events-table__host">{event.host ?? <span className="muted">–</span>}</td>
                {showSource && <td className="events-table__host">{event.source}</td>}
                <td className={`outcome outcome--${event.outcome}`}>{event.outcome}</td>
                <td className="events-table__message">{event.message}</td>
              </tr>
              {expanded && (
                <tr className="events-table__expanded">
                  <td />
                  <td colSpan={columns}>
                    <dl className="fields">
                      {DETAIL_FIELDS.filter((key) => event[key] !== null && event[key] !== undefined).map((key) => {
                        const filter = linkFor && pivotFilter(key, event[key]);
                        return (
                          <div key={key}>
                            <dt>{key}</dt>
                            <dd className="mono">
                              {filter ? (
                                <Link to={linkFor(filter)} title={`Show events with ${key} ${event[key]}`}>
                                  {String(event[key])}
                                </Link>
                              ) : (
                                String(event[key])
                              )}
                            </dd>
                          </div>
                        );
                      })}
                    </dl>
                    {event.raw && <pre className="raw">{event.raw}</pre>}
                    {linkFor && event.src_ip && (
                      <p className="events-table__block">
                        <Link to={`/blocked?ip=${encodeURIComponent(event.src_ip)}`}>Block {event.src_ip}…</Link>
                      </p>
                    )}
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </tbody>
    </table>
  );
}
