import { CircleCheck, CircleDot, Eye } from "lucide-react";
import "./StatusLabel.css";

export const STATUSES = [
  { id: "open", label: "Open", icon: CircleDot },
  { id: "acknowledged", label: "Acknowledged", icon: Eye },
  { id: "closed", label: "Closed", icon: CircleCheck },
];

/** Alert status as an icon plus its name. */
export default function StatusLabel({ status }) {
  const entry = STATUSES.find((s) => s.id === status) ?? { label: status, icon: CircleDot };
  const Icon = entry.icon;
  return (
    <span className={`status status--${status}`}>
      <Icon size={14} aria-hidden="true" />
      {entry.label}
    </span>
  );
}
