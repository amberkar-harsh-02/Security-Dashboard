import { useState } from "react";
import { Moon, Sun } from "lucide-react";

const KEY = "siem-theme";

function currentTheme() {
  const set = document.documentElement.dataset.theme;
  if (set === "light" || set === "dark") return set;
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export default function ThemeToggle() {
  const [theme, setTheme] = useState(currentTheme);
  const next = theme === "dark" ? "light" : "dark";

  function toggle() {
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem(KEY, next);
    } catch {
      // Without storage the theme still changes for this visit.
    }
    setTheme(next);
  }

  const Icon = theme === "dark" ? Sun : Moon;
  return (
    <button type="button" className="button button--quiet theme-toggle" onClick={toggle}>
      <Icon size={16} aria-hidden="true" />
      <span className="rail__label">{next === "light" ? "Light theme" : "Dark theme"}</span>
    </button>
  );
}
