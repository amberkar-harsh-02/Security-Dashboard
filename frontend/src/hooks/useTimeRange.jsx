import { createContext, useCallback, useContext, useMemo, useState } from "react";

// One time range for the whole app, chosen in the top bar. The overview's alert band
// can also set a custom window by brushing (phase 6), so a range is either a preset
// or an explicit {from, to}.

export const PRESETS = [
  { id: "1h", label: "1 hour", short: "1h", ms: 60 * 60 * 1000 },
  { id: "24h", label: "24 hours", short: "24h", ms: 24 * 60 * 60 * 1000 },
  { id: "7d", label: "7 days", short: "7d", ms: 7 * 24 * 60 * 60 * 1000 },
];

const STORAGE_KEY = "siem-range";
const TimeRangeContext = createContext(null);

function readSaved() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return PRESETS.some((p) => p.id === saved) ? saved : "24h";
  } catch {
    return "24h";
  }
}

export function TimeRangeProvider({ children }) {
  const [range, setRangeState] = useState(() => ({ preset: readSaved(), from: null, to: null }));

  const setPreset = useCallback((preset) => {
    try {
      localStorage.setItem(STORAGE_KEY, preset);
    } catch {
      // Storage can be unavailable (private windows); the choice still applies for this visit.
    }
    setRangeState({ preset, from: null, to: null });
  }, []);

  const setWindow = useCallback((from, to) => {
    setRangeState((current) => ({ preset: current.preset, from, to }));
  }, []);

  const value = useMemo(() => {
    const preset = PRESETS.find((p) => p.id === range.preset);
    return {
      preset: range.preset,
      custom: Boolean(range.from),
      setPreset,
      setWindow,
      clearWindow: () => setWindow(null, null),
      /** Current bounds as ISO strings. Presets are computed at call time so they stay current. */
      bounds() {
        if (range.from) return { from: range.from, to: range.to };
        const to = new Date();
        return { from: new Date(to.getTime() - preset.ms).toISOString(), to: to.toISOString() };
      },
    };
  }, [range, setPreset, setWindow]);

  return <TimeRangeContext.Provider value={value}>{children}</TimeRangeContext.Provider>;
}

export function useTimeRange() {
  const context = useContext(TimeRangeContext);
  if (!context) throw new Error("useTimeRange must be used inside TimeRangeProvider");
  return context;
}
