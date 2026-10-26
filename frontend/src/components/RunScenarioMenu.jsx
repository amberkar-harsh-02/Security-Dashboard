import { useEffect, useId, useRef, useState } from "react";
import { ChevronDown, Play } from "lucide-react";
import { api } from "../api/client";
import "./RunScenarioMenu.css";

// Attack scenarios from the backend simulator. They generate test data, so the menu
// says so plainly; results show in Alerts within a couple of seconds.

export default function RunScenarioMenu() {
  const [open, setOpen] = useState(false);
  const [scenarios, setScenarios] = useState(null);
  const [message, setMessage] = useState(null);
  const [running, setRunning] = useState(null);
  const menuId = useId();
  const root = useRef(null);
  const trigger = useRef(null);

  useEffect(() => {
    if (!open || scenarios) return;
    api
      .get("/simulate")
      .then((data) => setScenarios(data.scenarios))
      .catch((error) => setMessage({ error: true, text: error.message }));
  }, [open, scenarios]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (event) => {
      if (!root.current?.contains(event.target)) setOpen(false);
    };
    const onKey = (event) => {
      if (event.key === "Escape") {
        setOpen(false);
        trigger.current?.focus();
      }
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  useEffect(() => {
    if (!message) return undefined;
    const timer = setTimeout(() => setMessage(null), 6000);
    return () => clearTimeout(timer);
  }, [message]);

  async function run(scenario) {
    setRunning(scenario.id);
    try {
      const result = await api.post(`/simulate/${scenario.id}`);
      setMessage({ text: `${scenario.name}: sent ${result.events} events` });
      setOpen(false);
      trigger.current?.focus();
    } catch (error) {
      setMessage({ error: true, text: error.message });
    } finally {
      setRunning(null);
    }
  }

  return (
    <div className="scenario" ref={root}>
      <button
        ref={trigger}
        type="button"
        className="button"
        aria-expanded={open}
        aria-controls={menuId}
        onClick={() => setOpen((value) => !value)}
      >
        <Play size={14} aria-hidden="true" />
        Run scenario
        <ChevronDown size={14} aria-hidden="true" />
      </button>

      {open && (
        <div className="scenario__panel" id={menuId}>
          <p className="scenario__intro">Sends simulated attack traffic through the real parsers and rules.</p>
          {!scenarios && !message?.error && <p className="scenario__loading">Loading scenarios…</p>}
          {scenarios && (
            <ul className="scenario__list">
              {scenarios.map((scenario) => (
                <li key={scenario.id}>
                  <button
                    type="button"
                    className="scenario__item"
                    disabled={running !== null}
                    onClick={() => run(scenario)}
                  >
                    <span className="scenario__name">
                      {scenario.name}
                      {running === scenario.id && <span className="scenario__running"> sending…</span>}
                    </span>
                    <span className="scenario__desc">{scenario.description}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className={`scenario__toast${message?.error ? " scenario__toast--error" : ""}`} role="status">
        {message?.text}
      </div>
    </div>
  );
}
