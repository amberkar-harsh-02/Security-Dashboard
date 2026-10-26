import { useEffect, useState } from "react";
import { api } from "../api/client";

// Small lists that rarely change (analyst names, rule names). Fetched once per page load
// and shared between components.

const cache = new Map();

function useCached(key, load) {
  const [value, setValue] = useState(() => cache.get(key)?.value ?? null);

  useEffect(() => {
    let entry = cache.get(key);
    if (!entry) {
      entry = { promise: load(), value: null };
      cache.set(key, entry);
      entry.promise.then(
        (result) => {
          entry.value = result;
        },
        () => cache.delete(key),
      );
    }
    let cancelled = false;
    entry.promise.then(
      (result) => !cancelled && setValue(result),
      () => {},
    );
    return () => {
      cancelled = true;
    };
  }, [key, load]);

  return value;
}

const loadUsers = () => api.get("/auth/users").then((data) => data.users);
const loadRules = () => api.get("/rules").then((data) => data.rules);

/** Analyst usernames, for assigning alerts. */
export function useUsers() {
  return useCached("users", loadUsers) ?? [];
}

/** Detection rules (id, name, severity, ...), for filters. */
export function useRules() {
  return useCached("rules", loadRules) ?? [];
}

/** Forget cached lists (after sign-out, or in tests). */
export function clearLookups() {
  cache.clear();
}
