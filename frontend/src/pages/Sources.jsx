import { useEffect } from "react";
import { Link } from "react-router";
import { TriangleAlert } from "lucide-react";
import { API_BASE, api } from "../api/client";
import HostHealth from "../components/HostHealth";
import { useApi } from "../hooks/useApi";
import { formatDateTime, formatNumber, formatRelative } from "../lib/format";
import "./Sources.css";

// A source that sent nothing for this long is flagged as quiet: a broken collector
// or a stopped service looks exactly like a quiet network, so analysts need to see it.
const QUIET_MINUTES = 15;

export function isQuiet(lastSeen, now = Date.now()) {
  return now - new Date(lastSeen).getTime() > QUIET_MINUTES * 60 * 1000;
}

function eventsLink(source) {
  const params = new URLSearchParams({ source: source.source });
  if (source.host) params.set("host", source.host);
  return `/events?${params}`;
}

function Collectors({ collectors }) {
  if (!collectors) return null;
  const { syslog, host_agent: agent, simulator, ingest_api: ingest } = collectors;
  const ingestUrl = `${window.location.origin}${API_BASE}/ingest`;
  return (
    <dl className="collectors">
      <div>
        <dt>Syslog</dt>
        <dd>
          {syslog.enabled ? (
            <>
              Listening on <code>udp://{syslog.host}:{syslog.port}</code>
              {syslog.host === "127.0.0.1" && (
                <p className="muted">Only this machine can send. Set SIEM_SYSLOG_HOST=0.0.0.0 to accept other devices.</p>
              )}
            </>
          ) : (
            <span className="muted">Off. Set SIEM_SYSLOG_PORT to turn it on.</span>
          )}
        </dd>
      </div>
      <div>
        <dt>HTTP ingest</dt>
        <dd>
          <code>POST {ingestUrl}</code> for JSON, <code>{ingestUrl}/raw</code> for log lines, with an{" "}
          <code>X-API-Key</code> header.
          {ingest.default_key && (
            <p className="collectors__warn">
              <TriangleAlert size={14} aria-hidden="true" />
              The ingest key is still the default. Set SIEM_INGEST_KEY before exposing the server.
            </p>
          )}
        </dd>
      </div>
      <div>
        <dt>Host agent</dt>
        <dd>
          {agent.enabled ? (
            `Recording processes, listening ports and outbound connections on the SIEM host every ${agent.interval_seconds} seconds.`
          ) : (
            <span className="muted">Off.</span>
          )}
        </dd>
      </div>
      <div>
        <dt>Simulator</dt>
        <dd>
          {simulator.enabled
            ? simulator.noise_per_second > 0
              ? `On. Writes about ${simulator.noise_per_second} background ${simulator.noise_per_second === 1 ? "event" : "events"} per second as test data.`
              : "On for scenarios. Background test data is off."
            : <span className="muted">Off.</span>}
        </dd>
      </div>
    </dl>
  );
}

export default function Sources() {
  const result = useApi((signal) => api.get("/sources", undefined, { signal }), []);
  const { reload } = result;

  useEffect(() => {
    const timer = setInterval(reload, 30000);
    return () => clearInterval(timer);
  }, [reload]);

  const sources = result.data?.sources ?? [];
  const quiet = sources.filter((s) => isQuiet(s.last_seen));

  return (
    <div className="page sources">
      <div className="page__header">
        <h1>Sources</h1>
        <p className="muted">Everything that sent events in the last 24 hours</p>
      </div>

      {result.error && (
        <p className="notice notice--error" role="alert">
          {result.error.message}
        </p>
      )}

      <div className="sources__grid">
        <section className="section" aria-labelledby="sources-heading">
          <div className="section__head">
            <h2 id="sources-heading">Log sources</h2>
            {quiet.length > 0 && (
              <span className="sources__quiet-count">
                {quiet.length} quiet for over {QUIET_MINUTES} minutes
              </span>
            )}
          </div>
          {result.data && !sources.length && (
            <p className="empty">No events in the last 24 hours. Send logs to one of the collectors on the right.</p>
          )}
          {sources.length > 0 && (
            <table className={`table${result.loading ? " is-refreshing" : ""}`}>
              <thead>
                <tr>
                  <th scope="col">Source</th>
                  <th scope="col">Host</th>
                  <th scope="col">Last event</th>
                  <th scope="col" className="num">
                    Last hour
                  </th>
                  <th scope="col" className="num">
                    Last 24 hours
                  </th>
                </tr>
              </thead>
              <tbody>
                {sources.map((source) => {
                  const stale = isQuiet(source.last_seen);
                  return (
                    <tr key={`${source.source}|${source.host}`}>
                      <td>
                        <Link to={eventsLink(source)}>{source.source}</Link>
                      </td>
                      <td className="mono">{source.host ?? <span className="muted">–</span>}</td>
                      <td title={formatDateTime(source.last_seen)}>
                        {stale ? (
                          <span className="sources__stale">
                            <TriangleAlert size={14} aria-hidden="true" />
                            {formatRelative(source.last_seen)}
                            <span className="visually-hidden"> (quiet)</span>
                          </span>
                        ) : (
                          formatRelative(source.last_seen)
                        )}
                      </td>
                      <td className="num">{formatNumber(source.events_1h)}</td>
                      <td className="num">{formatNumber(source.events_24h)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>

        <div className="sources__side">
          <section className="section" aria-labelledby="collectors-heading">
            <div className="section__head">
              <h2 id="collectors-heading">How logs arrive</h2>
            </div>
            <Collectors collectors={result.data?.collectors} />
          </section>

          <section className="section" aria-labelledby="host-heading">
            <div className="section__head">
              <h2 id="host-heading">SIEM host</h2>
            </div>
            <HostHealth />
          </section>
        </div>
      </div>
    </div>
  );
}
