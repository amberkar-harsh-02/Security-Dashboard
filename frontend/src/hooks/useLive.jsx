import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import { API_BASE } from "../api/client";

// Live updates from /api/stream (server-sent events). The browser reconnects on its own
// when the server closes the stream. Pages subscribe to alert changes with useAlertFeed.

const LiveContext = createContext(null);

export function LiveProvider({ children }) {
  const [status, setStatus] = useState("connecting"); // connecting | live | reconnecting
  const [stats, setStats] = useState({ events_last_minute: null, open_alerts: null });
  const listeners = useRef(new Set());

  useEffect(() => {
    if (typeof EventSource === "undefined") return undefined;
    const source = new EventSource(`${API_BASE}/stream`);
    source.onopen = () => setStatus("live");
    source.onerror = () => setStatus("reconnecting");
    source.addEventListener("stats", (event) => {
      setStatus("live");
      setStats(JSON.parse(event.data));
    });
    source.addEventListener("alert", (event) => {
      const payload = JSON.parse(event.data);
      // Count new alerts right away; the next stats message corrects any drift.
      if (payload.created && payload.alert.status === "open") {
        setStats((current) =>
          current.open_alerts === null ? current : { ...current, open_alerts: current.open_alerts + 1 },
        );
      }
      listeners.current.forEach((listener) => listener(payload));
    });
    return () => source.close();
  }, []);

  const value = useMemo(
    () => ({
      status,
      stats,
      subscribe(listener) {
        listeners.current.add(listener);
        return () => listeners.current.delete(listener);
      },
    }),
    [status, stats],
  );

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive() {
  const context = useContext(LiveContext);
  if (!context) throw new Error("useLive must be used inside LiveProvider");
  return context;
}

/** Call `onAlert({created, alert})` for every alert created or changed while mounted. */
export function useAlertFeed(onAlert) {
  const { subscribe } = useLive();
  const handler = useRef(onAlert);
  handler.current = onAlert;
  useEffect(() => subscribe((payload) => handler.current(payload)), [subscribe]);
}
