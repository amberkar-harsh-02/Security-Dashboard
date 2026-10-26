// Formatting helpers. Times from the API are ISO 8601 UTC; the UI shows local time.

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const numberFormat = new Intl.NumberFormat();
const compactFormat = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });

export function formatNumber(value) {
  return value === null || value === undefined ? "–" : numberFormat.format(value);
}

/** 1,284 stays exact; 12,900 becomes 12.9K. */
export function formatCompact(value) {
  if (value === null || value === undefined) return "–";
  return Math.abs(value) < 10000 ? numberFormat.format(value) : compactFormat.format(value);
}

function toDate(value) {
  return value instanceof Date ? value : new Date(value);
}

export function formatClock(value) {
  return toDate(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function formatDateTime(value) {
  return toDate(value).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatDateMinute(value) {
  return toDate(value).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function formatDay(value) {
  return toDate(value).toLocaleDateString([], { weekday: "short", day: "numeric" });
}

/** "just now", "4 min ago", "3 h ago", "2 days ago". */
export function formatRelative(value, now = Date.now()) {
  const seconds = Math.round((now - toDate(value).getTime()) / 1000);
  if (seconds < 45) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 36) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  return `${days} ${days === 1 ? "day" : "days"} ago`;
}

/** Bucket span as "14:00 – 15:00", with the day when the span is a day or longer. */
export function formatSpan(startMs, endMs) {
  const multiDay = endMs - startMs >= 6 * 60 * 60 * 1000;
  const start = multiDay ? `${formatDay(startMs)} ${formatClock(startMs)}` : formatClock(startMs);
  const end = multiDay ? `${formatDay(endMs)} ${formatClock(endMs)}` : formatClock(endMs);
  return `${start} – ${end}`;
}

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"];

/** 1536 -> "1.5 KB". Uses 1024 steps, like operating system tools. */
export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return "–";
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${BYTE_UNITS[unit]}`;
}

export function formatRate(bytesPerSecond) {
  return `${formatBytes(bytesPerSecond)}/s`;
}

/** 273600 -> "3 d 4 h". */
export function formatDuration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days} d ${hours} h`;
  if (hours) return `${hours} h ${minutes} min`;
  return `${minutes} min`;
}
