// Plain-language descriptions of detection rules, shared by the alert and rules pages.

export const FIELD_LABELS = {
  src_ip: "Source address",
  dst_ip: "Destination address",
  user: "Account",
  host: "Host",
  dst_port: "Destination port",
  process: "Process",
};

export function formatWindow(seconds) {
  if (seconds % 86400 === 0) return `${seconds / 86400} ${seconds === 86400 ? "day" : "days"}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} ${seconds === 3600 ? "hour" : "hours"}`;
  if (seconds % 60 === 0) return `${seconds / 60} ${seconds === 60 ? "minute" : "minutes"}`;
  return `${seconds} seconds`;
}

/** One sentence on what makes this rule fire, from its type and settings. */
export function describeTrigger(rule) {
  if (!rule) return null;
  const per = rule.group_by?.length ? ` from the same ${rule.group_by.map((f) => FIELD_LABELS[f]?.toLowerCase() ?? f).join(" and ")}` : "";
  const window = formatWindow(rule.window_seconds);
  switch (rule.type) {
    case "threshold":
      return `Fires when ${rule.threshold} or more matching events arrive within ${window}${per}.`;
    case "distinct":
      return `Fires when ${rule.threshold} or more different ${rule.field ?? "values"} values appear within ${window}${per}.`;
    case "sequence":
      return `Fires when a run of matching events is followed by a second kind of event within ${window}${per}.`;
    case "ioc":
      return `Fires when ${rule.field ?? "a field"} matches the threat intelligence list.`;
    default:
      return "Fires on each matching event. Repeat matches are added to this alert.";
  }
}

export function mitreUrl(technique) {
  return `https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`;
}
