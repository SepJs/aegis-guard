import type { Confidence } from "../types";
export default function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  const cls = confidence === "high" ? "badge--high" : confidence === "medium" ? "badge--medium" : "badge--low";
  return <span className={`badge ${cls}`}>{confidence.toUpperCase()}</span>;
}
