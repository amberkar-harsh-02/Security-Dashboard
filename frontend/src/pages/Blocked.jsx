import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { ShieldBan, TriangleAlert } from "lucide-react";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import { BLOCK_DURATIONS, describeActor, formatTimeLeft, fromValue, toValue } from "../lib/blocks";
import { formatDateTime, formatRelative } from "../lib/format";
import "./Blocked.css";

// Addresses blocked at the server firewall: who blocked them, why, and for how long.

function Enforcement({ status }) {
  if (!status) return null;
  if (status.mode === "record-only") {
    return (
      <p className="notice">
        Blocks are recorded but not enforced: this SIEM is not connected to a firewall. On the server, blocks are applied
        by the nftables sync in <code>deploy/</code>.
      </p>
    );
  }
  if (status.error) {
    return (
      <p className="notice notice--error" role="alert">
        <TriangleAlert size={14} aria-hidden="true" /> The firewall did not apply the latest blocklist: {status.error}
      </p>
    );
  }
  return (
    <p className="notice blocked__enforced">
      <ShieldBan size={16} aria-hidden="true" />
      Enforced by the server firewall: all traffic from these addresses is dropped. Last applied{" "}
      {status.last_applied_at ? formatRelative(status.last_applied_at) : "never"}.
    </p>
  );
}

function BlockForm({ initialIp, onBlocked }) {
  const [ip, setIp] = useState(initialIp);
  const [minutes, setMinutes] = useState("60");
  const [reason, setReason] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => setIp(initialIp), [initialIp]);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const block = await api.post("/blocks", { ip: ip.trim(), minutes: fromValue(minutes), reason });
      setIp("");
      setReason("");
      onBlocked(block);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="block-form" onSubmit={submit}>
      <label className="block-form__field">
        <span>Address</span>
        <input className="input mono" required placeholder="203.0.113.9" value={ip} onChange={(e) => setIp(e.target.value)} />
      </label>
      <label className="block-form__field">
        <span>For</span>
        <select className="input" value={minutes} onChange={(e) => setMinutes(e.target.value)}>
          {BLOCK_DURATIONS.map((d) => (
            <option key={d.label} value={toValue(d.minutes)}>
              {d.label}
            </option>
          ))}
        </select>
      </label>
      <label className="block-form__field block-form__reason">
        <span>Reason (optional)</span>
        <input className="input" maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
      </label>
      <button type="submit" className="button button--primary" disabled={busy || !ip.trim()}>
        {busy ? "Blocking…" : "Block"}
      </button>
      {error && (
        <p className="block-form__error" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}

function BlockRows({ blocks, onUnblock, history }) {
  return (
    <table className="table">
      <thead>
        <tr>
          <th scope="col">Address</th>
          <th scope="col">Reason</th>
          <th scope="col">Blocked by</th>
          <th scope="col">Since</th>
          <th scope="col">{history ? "Ended" : "Time left"}</th>
          {!history && (
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          )}
        </tr>
      </thead>
      <tbody>
        {blocks.map((block) => (
          <tr key={block.id}>
            <td>
              <Link className="mono" to={`/events?ip=${encodeURIComponent(block.ip)}`}>
                {block.ip}
              </Link>
            </td>
            <td className={block.reason ? undefined : "muted"}>{block.reason ?? "–"}</td>
            <td>{describeActor(block.created_by)}</td>
            <td title={formatDateTime(block.created_at)}>{formatRelative(block.created_at)}</td>
            <td>
              {history
                ? block.removed_at
                  ? `Unblocked by ${block.removed_by} ${formatRelative(block.removed_at)}`
                  : `Expired ${formatRelative(block.expires_at)}`
                : formatTimeLeft(block.expires_at)}
            </td>
            {!history && (
              <td className="blocked__action">
                <button type="button" className="button" onClick={() => onUnblock(block)}>
                  Unblock
                </button>
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Blocked() {
  const [params] = useSearchParams();
  const result = useApi((signal) => api.get("/blocks", undefined, { signal }), []);
  const [message, setMessage] = useState(null);
  const data = result.data;

  async function unblock(block) {
    setMessage(null);
    try {
      await api.post(`/blocks/${block.id}/unblock`);
      setMessage(`Unblocked ${block.ip}.`);
      result.reload();
    } catch (err) {
      setMessage(err.message);
    }
  }

  return (
    <div className="page blocked">
      <div className="page__header">
        <h1>Blocked addresses</h1>
        {data && (
          <p className="muted">
            {data.active.length} active {data.active.length === 1 ? "block" : "blocks"}
          </p>
        )}
      </div>

      <Enforcement status={data?.enforcement} />

      <section className="section" aria-labelledby="block-heading">
        <div className="section__head">
          <h2 id="block-heading">Block an address</h2>
        </div>
        <BlockForm
          initialIp={params.get("ip") ?? ""}
          onBlocked={(block) => {
            setMessage(`Blocked ${block.ip}.`);
            result.reload();
          }}
        />
        <p className="muted blocked__help">
          Your own address, internal networks and the server&apos;s addresses are refused. Rules can also block on their own:
          see <Link to="/rules">Rules</Link>.
        </p>
      </section>

      <p className="blocked__message" role="status">
        {message}
      </p>

      {result.error && (
        <p className="notice notice--error" role="alert">
          {result.error.message}
        </p>
      )}

      {data && (
        <>
          <section className="section" aria-labelledby="active-heading">
            <div className="section__head">
              <h2 id="active-heading">Active</h2>
            </div>
            {data.active.length ? (
              <BlockRows blocks={data.active} onUnblock={unblock} />
            ) : (
              <p className="empty">No addresses are blocked. Block one above, or from an alert.</p>
            )}
          </section>

          {data.history.length > 0 && (
            <section className="section" aria-labelledby="history-heading">
              <div className="section__head">
                <h2 id="history-heading">Ended</h2>
              </div>
              <BlockRows blocks={data.history} history />
            </section>
          )}
        </>
      )}
    </div>
  );
}
