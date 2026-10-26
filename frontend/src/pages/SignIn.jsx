import { useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { useAuth } from "../auth/AuthProvider";
import "./SignIn.css";

export default function SignIn() {
  const { status, signIn } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const next = location.state?.from || "/";
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  if (status === "signed-in") return <Navigate to={next} replace />;

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signIn(username.trim(), password);
      navigate(next, { replace: true });
    } catch (err) {
      setError(err.message);
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="signin">
      <div className="signin__column">
        <div className="signin__brand">
          <svg className="brand__mark" viewBox="0 0 32 32" aria-hidden="true">
            <rect width="32" height="32" rx="6" />
            <path d="M7 21h4l3-9 4 13 3-7h4" />
          </svg>
          <span>Security Dashboard</span>
        </div>

        <h1 className="signin__title">Sign in</h1>
        <p className="signin__lede">Review alerts, search events and manage detection rules.</p>

        <form className="signin__form" onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              className="input"
              autoComplete="username"
              autoFocus
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              className="input"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>

          {error && (
            <p className="signin__error" role="alert">
              {error}
            </p>
          )}

          <button className="button button--primary signin__submit" type="submit" disabled={busy || !username || !password}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p className="signin__help">
          First sign-in: the password for <code>admin</code> is printed in the backend console when the server
          starts for the first time. Change it with <code>python manage.py set-password admin</code>.
        </p>
      </div>
    </main>
  );
}
