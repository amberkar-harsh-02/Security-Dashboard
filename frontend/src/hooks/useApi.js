import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Load data with `load(signal)` whenever `deps` change.
 * Returns { data, error, loading, reload }. Earlier requests are aborted when deps change.
 */
export function useApi(load, deps) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const loader = useRef(load);
  loader.current = load;
  const controller = useRef(null);

  const run = useCallback(() => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setState((s) => ({ ...s, loading: true, error: null }));
    loader
      .current(current.signal)
      .then((data) => {
        if (!current.signal.aborted) setState({ data, error: null, loading: false });
      })
      .catch((error) => {
        if (error.name !== "AbortError" && !current.signal.aborted) {
          setState((s) => ({ ...s, error, loading: false }));
        }
      });
  }, []);

  useEffect(() => {
    run();
    return () => controller.current?.abort();
  }, deps);

  return { ...state, reload: run };
}
