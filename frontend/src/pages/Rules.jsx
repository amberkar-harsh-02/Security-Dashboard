import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router";
import { ExternalLink, RefreshCw } from "lucide-react";
import { api } from "../api/client";
import SeverityBadge from "../components/SeverityBadge";
import Switch from "../components/Switch";
import { useApi } from "../hooks/useApi";
import { clearLookups } from "../hooks/useLookups";
import { AUTO_BLOCK_DURATIONS, fromValue, toValue } from "../lib/blocks";
import { formatNumber } from "../lib/format";
import { describeTrigger, mitreUrl } from "../lib/rules";
import "./Rules.css";

const isScalar = (value) => value === null || typeof value !== "object";

function scalar(value) {
  if (typeof value === "string") {
    // Folded YAML text (description: >) arrives with a trailing newline. Spaces can be
    // part of a match value, so only newlines are removed.
    value = value.replace(/\n+$/, "");
    const plain = /^[\w./@-][\w ./@-]*$/.test(value) && !/^(true|false|null|yes|no|\d)/i.test(value);
    return plain ? value : JSON.stringify(value);
  }
  return String(value);
}

/** Minimal YAML rendering of a rule definition, for reading only. */
export function toYaml(value, indent = "") {
  if (Array.isArray(value)) {
    if (value.every(isScalar)) return `[${value.map(scalar).join(", ")}]`;
    return value.map((item) => `${indent}- ${toYaml(item, `${indent}  `).trimStart()}`).join("\n");
  }
  if (!isScalar(value)) {
    return Object.entries(value)
      .map(([key, item]) =>
        isScalar(item) || (Array.isArray(item) && item.every(isScalar))
          ? `${indent}${key}: ${toYaml(item)}`
          : `${indent}${key}:\n${toYaml(item, `${indent}  `)}`,
      )
      .join("\n");
  }
  return scalar(value);
}

function RuleRow({ rule, onToggle, onAutoBlock, highlighted }) {
  const [showDefinition, setShowDefinition] = useState(false);
  const [busy, setBusy] = useState(false);

  async function toggle(enabled) {
    setBusy(true);
    try {
      await onToggle(rule, enabled);
    } finally {
      setBusy(false);
    }
  }

  return (
    <li id={rule.id} className={`rule${rule.enabled ? "" : " rule--off"}${highlighted ? " rule--target" : ""}`}>
      <div className="rule__switch">
        <Switch checked={rule.enabled} onChange={toggle} disabled={busy} label={`${rule.name}: ${rule.enabled ? "on" : "off"}`} />
      </div>
      <div className="rule__body">
        <div className="rule__head">
          <h2 className="rule__name">{rule.name}</h2>
          <SeverityBadge severity={rule.severity} />
          {!rule.enabled && <span className="rule__state">Off</span>}
        </div>
        <p className="rule__description">{rule.description}</p>
        <p className="rule__trigger">{describeTrigger(rule)}</p>
        <div className="rule__meta">
          {rule.mitre?.technique && (
            <a href={mitreUrl(rule.mitre.technique)} target="_blank" rel="noopener noreferrer">
              {rule.mitre.technique} {rule.mitre.name}
              <ExternalLink size={12} aria-label="(opens in a new tab)" />
            </a>
          )}
          {rule.can_auto_block && (
            <label className="rule__auto-block">
              <span>Auto-block the source for</span>
              <select
                className="input"
                value={toValue(rule.auto_block_minutes)}
                disabled={busy}
                onChange={async (event) => {
                  setBusy(true);
                  try {
                    await onAutoBlock(rule, fromValue(event.target.value));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {AUTO_BLOCK_DURATIONS.map((d) => (
                  <option key={d.label} value={toValue(d.minutes)}>
                    {d.minutes === null ? "Off (alert only)" : d.label}
                  </option>
                ))}
              </select>
            </label>
          )}
          <button
            type="button"
            className="button button--quiet"
            aria-expanded={showDefinition}
            onClick={() => setShowDefinition((value) => !value)}
          >
            {showDefinition ? "Hide definition" : "Show definition"}
          </button>
        </div>
        {showDefinition && <pre className="raw rule__definition">{toYaml(rule.definition)}</pre>}
      </div>
      <div className="rule__count">
        <Link to={`/alerts?status=all&rule_id=${encodeURIComponent(rule.id)}`}>
          <strong>{formatNumber(rule.alerts_24h)}</strong> {rule.alerts_24h === 1 ? "alert" : "alerts"}
        </Link>
        <span className="muted">last 24 hours</span>
      </div>
    </li>
  );
}

export default function Rules() {
  const location = useLocation();
  const target = location.hash.slice(1);
  const [rules, setRules] = useState(null);
  const [message, setMessage] = useState(null);
  const [reloading, setReloading] = useState(false);

  const loaded = useApi((signal) => api.get("/rules", undefined, { signal }), []);
  useEffect(() => {
    if (loaded.data) setRules(loaded.data.rules);
  }, [loaded.data]);

  // Links like /rules#port-scan scroll to that rule once the list is on screen.
  useEffect(() => {
    if (rules && target) document.getElementById(target)?.scrollIntoView({ block: "center" });
  }, [rules, target]);

  async function toggle(rule, enabled) {
    setMessage(null);
    setRules((current) => current.map((r) => (r.id === rule.id ? { ...r, enabled } : r)));
    try {
      const updated = await api.patch(`/rules/${rule.id}`, { enabled });
      setRules((current) => current.map((r) => (r.id === rule.id ? updated : r)));
      setMessage({ text: `${rule.name} is ${enabled ? "on" : "off"}.` });
    } catch (error) {
      setRules((current) => current.map((r) => (r.id === rule.id ? rule : r)));
      setMessage({ error: true, text: error.message });
    }
  }

  async function setAutoBlock(rule, minutes) {
    setMessage(null);
    try {
      const updated = await api.patch(`/rules/${rule.id}`, { auto_block_minutes: minutes });
      setRules((current) => current.map((r) => (r.id === rule.id ? updated : r)));
      const label = AUTO_BLOCK_DURATIONS.find((d) => d.minutes === minutes)?.label.toLowerCase();
      setMessage({
        text:
          minutes === null
            ? `${rule.name} no longer blocks on its own.`
            : `${rule.name} now blocks the source address for ${label} when it raises a new alert.`,
      });
    } catch (error) {
      setMessage({ error: true, text: error.message });
    }
  }

  async function reload() {
    setReloading(true);
    setMessage(null);
    try {
      const result = await api.post("/rules/reload");
      setRules(result.rules);
      clearLookups();
      setMessage({ text: `Reloaded ${result.rules.length} rules from the rule files.` });
    } catch (error) {
      setMessage({ error: true, text: `Rule files not reloaded. The previous rules stay active. ${error.message}` });
    } finally {
      setReloading(false);
    }
  }

  const enabledCount = rules?.filter((r) => r.enabled).length ?? 0;

  return (
    <div className="page rules">
      <div className="page__header rules__header">
        <h1>Rules</h1>
        {rules && (
          <p className="muted">
            {rules.length} rules, {enabledCount} on
          </p>
        )}
        <button type="button" className="button rules__reload" onClick={reload} disabled={reloading}>
          <RefreshCw size={14} aria-hidden="true" />
          {reloading ? "Reloading…" : "Reload rule files"}
        </button>
      </div>
      <p className="page__lede rules__lede">
        Rules live in <code>backend/rules/*.yml</code>. Edit a file, then reload to apply it without restarting the server.
        Turning a rule off stops new alerts; existing alerts stay.
      </p>

      <p className={`rules__message${message?.error ? " rules__message--error" : ""}`} role="status">
        {message?.text}
      </p>

      {loaded.error && (
        <p className="notice notice--error" role="alert">
          {loaded.error.message}
        </p>
      )}

      {rules && (
        <ul className="rule-list">
          {rules.map((rule) => (
            <RuleRow key={rule.id} rule={rule} onToggle={toggle} onAutoBlock={setAutoBlock} highlighted={rule.id === target} />
          ))}
        </ul>
      )}
    </div>
  );
}
