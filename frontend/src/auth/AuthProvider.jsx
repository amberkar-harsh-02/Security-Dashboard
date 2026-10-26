import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api, setCsrfToken, setUnauthorizedHandler } from "../api/client";
import { clearLookups } from "../hooks/useLookups";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  // "loading" until the first /auth/me answer, then "signed-in" or "signed-out".
  const [state, setState] = useState({ status: "loading", user: null });

  const signedOut = useCallback(() => {
    setCsrfToken(null);
    clearLookups();
    setState({ status: "signed-out", user: null });
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(signedOut);
    let cancelled = false;
    api
      .get("/auth/me")
      .then((me) => {
        if (cancelled) return;
        setCsrfToken(me.csrf_token);
        setState({ status: "signed-in", user: me.user });
      })
      .catch(() => {
        if (!cancelled) signedOut();
      });
    return () => {
      cancelled = true;
    };
  }, [signedOut]);

  const signIn = useCallback(async (username, password) => {
    const result = await api.post("/auth/login", { username, password });
    setCsrfToken(result.csrf_token);
    setState({ status: "signed-in", user: result.user });
    return result.user;
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      signedOut();
    }
  }, [signedOut]);

  const value = useMemo(() => ({ ...state, signIn, signOut }), [state, signIn, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
