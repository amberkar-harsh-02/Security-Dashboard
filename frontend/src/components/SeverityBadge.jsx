import { SEVERITY_LABELS } from "../lib/format";
import "./SeverityBadge.css";

/** Severity as a colored mark plus its name. Color never carries the meaning alone. */
export default function SeverityBadge({ severity }) {
  return (
    <span className={`sev sev--${severity}`}>
      <span className="sev__mark" aria-hidden="true" />
      {SEVERITY_LABELS[severity] ?? severity}
    </span>
  );
}
