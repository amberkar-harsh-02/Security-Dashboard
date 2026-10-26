// Block durations offered in the dashboard (minutes; null = permanent), matching the API.

export const BLOCK_DURATIONS = [
  { minutes: 15, label: "15 minutes" },
  { minutes: 60, label: "1 hour" },
  { minutes: 1440, label: "24 hours" },
  { minutes: 10080, label: "7 days" },
  { minutes: null, label: "Permanently" },
];

export const AUTO_BLOCK_DURATIONS = [
  { minutes: null, label: "Off" },
  { minutes: 15, label: "15 minutes" },
  { minutes: 60, label: "1 hour" },
  { minutes: 1440, label: "24 hours" },
];

/** Select values are strings; "" stands for null. */
export const toValue = (minutes) => (minutes === null ? "" : String(minutes));
export const fromValue = (value) => (value === "" ? null : Number(value));

/** "42 min left", "5 h left", "Permanent". */
export function formatTimeLeft(expiresAt, now = Date.now()) {
  if (!expiresAt) return "Permanent";
  const minutes = Math.max(0, Math.round((Date.parse(expiresAt) - now) / 60000));
  if (minutes < 60) return `${minutes} min left`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h left`;
  return `${Math.round(hours / 24)} days left`;
}

/** "rule:ssh-brute-force" -> "Auto-block (ssh-brute-force)". */
export function describeActor(actor) {
  return actor?.startsWith("rule:") ? `Auto-block (${actor.slice(5)})` : actor;
}
