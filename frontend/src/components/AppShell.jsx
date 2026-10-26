import { useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { Activity, Cpu, FileCode2, Gauge, LogOut, Radio, Search, ShieldBan, Siren } from "lucide-react";
import { useAuth } from "../auth/AuthProvider";
import { PRESETS, useTimeRange } from "../hooks/useTimeRange";
import { useLive } from "../hooks/useLive";
import RunScenarioMenu from "./RunScenarioMenu";
import ThemeToggle from "./ThemeToggle";
import "./AppShell.css";

const NAV = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/alerts", label: "Alerts", icon: Siren, badge: true },
  { to: "/events", label: "Events", icon: Activity },
  { to: "/rules", label: "Rules", icon: FileCode2 },
  { to: "/sources", label: "Sources", icon: Radio },
  { to: "/blocked", label: "Blocked", icon: ShieldBan },
  { to: "/performance", label: "Performance", icon: Cpu },
];

function BrandMark() {
  return (
    <svg className="brand__mark" viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="6" />
      <path d="M7 21h4l3-9 4 13 3-7h4" />
    </svg>
  );
}

function LiveStatus() {
  const { status, stats } = useLive();
  const label = status === "live" ? "Live" : status === "connecting" ? "Connecting" : "Reconnecting";
  return (
    <div className={`live live--${status}`} role="status" aria-live="polite">
      <span className="live__dot" aria-hidden="true" />
      <span>{label}</span>
      {status === "live" && stats.events_last_minute !== null && (
        <span className="live__rate">{stats.events_last_minute.toLocaleString()} events/min</span>
      )}
    </div>
  );
}

function TimeRangePicker() {
  const { preset, custom, setPreset } = useTimeRange();
  return (
    <fieldset className="segmented" aria-label="Time range">
      <legend className="visually-hidden">Time range</legend>
      {PRESETS.map((option) => (
        <label key={option.id} className="segmented__option" title={`Last ${option.label}`}>
          <input
            type="radio"
            name="time-range"
            value={option.id}
            checked={!custom && preset === option.id}
            onChange={() => setPreset(option.id)}
          />
          <span>{option.short}</span>
        </label>
      ))}
    </fieldset>
  );
}

function GlobalSearch() {
  const navigate = useNavigate();
  const [text, setText] = useState("");
  return (
    <form
      className="search"
      role="search"
      onSubmit={(event) => {
        event.preventDefault();
        const query = text.trim();
        navigate(query ? `/events?q=${encodeURIComponent(query)}` : "/events");
      }}
    >
      <Search className="search__icon" size={16} aria-hidden="true" />
      <label htmlFor="global-search" className="visually-hidden">
        Search events
      </label>
      <input
        id="global-search"
        className="input search__input"
        type="search"
        placeholder="Search events by IP, user or text"
        value={text}
        onChange={(event) => setText(event.target.value)}
      />
    </form>
  );
}

export default function AppShell() {
  const { user, signOut } = useAuth();
  const { stats } = useLive();
  // The Performance page has its own short time window; the security time range does not apply there.
  const showTimeRange = useLocation().pathname !== "/performance";

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>

      <nav className="rail" aria-label="Main">
        <div className="brand">
          <BrandMark />
          <span className="brand__name">Security Dashboard</span>
        </div>

        <ul className="rail__nav">
          {NAV.map(({ to, label, icon: Icon, end, badge }) => (
            <li key={to}>
              <NavLink to={to} end={end} className="rail__link">
                <Icon size={18} aria-hidden="true" />
                <span className="rail__label">{label}</span>
                {badge && stats.open_alerts > 0 && (
                  <span className="rail__badge" aria-label={`${stats.open_alerts} open`}>
                    {stats.open_alerts}
                  </span>
                )}
              </NavLink>
            </li>
          ))}
        </ul>

        <div className="rail__footer">
          <ThemeToggle />
          <div className="rail__user">
            <span className="rail__username" title={`Signed in as ${user}`}>
              {user}
            </span>
            <button type="button" className="button button--quiet rail__signout" onClick={signOut}>
              <LogOut size={16} aria-hidden="true" />
              <span className="rail__label">Sign out</span>
            </button>
          </div>
        </div>
      </nav>

      <header className="topbar">
        <GlobalSearch />
        {showTimeRange && <TimeRangePicker />}
        <div className="topbar__end">
          <LiveStatus />
          <RunScenarioMenu />
        </div>
      </header>

      <main id="main" className="content" tabIndex={-1}>
        <Outlet />
      </main>
    </div>
  );
}
