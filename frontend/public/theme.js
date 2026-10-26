// Apply the saved theme before first paint to avoid a flash. Loaded as a file, not
// inline, so the Content Security Policy can forbid inline scripts.
try {
  var theme = localStorage.getItem("siem-theme");
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
} catch (e) {}
