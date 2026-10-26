import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";

const KEEP_MS = 60 * 60 * 1000;

/**
 * Poll /api/performance every `intervalMs`, asking only for samples newer than the last one.
 * Polling pauses while the browser tab is hidden. On an error the last data stays on screen.
 */
export function usePerformance(intervalMs = 2000) {
  const [state, setState] = useState({ snapshot: null, history: [], error: null });
  const lastT = useRef(null);

  useEffect(() => {
    let cancelled = false;
    let timer = null;

    async function poll() {
      if (document.visibilityState === "hidden") {
        timer = setTimeout(poll, intervalMs);
        return;
      }
      try {
        const snapshot = await api.get("/performance", lastT.current ? { since: lastT.current } : undefined);
        if (cancelled) return;
        if (snapshot.history.length) lastT.current = snapshot.history.at(-1).t;
        setState((current) => {
          const merged = [...current.history, ...snapshot.history];
          const cutoff = (merged.at(-1)?.t ?? 0) - KEEP_MS;
          return { snapshot, history: merged.filter((p) => p.t >= cutoff), error: null };
        });
      } catch (error) {
        if (!cancelled) setState((current) => ({ ...current, error }));
      }
      if (!cancelled) timer = setTimeout(poll, intervalMs);
    }

    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [intervalMs]);

  return state;
}
