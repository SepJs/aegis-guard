import type { Confidence } from "../types";
interface Props { confidence: Confidence; }
export default function ConfidenceBadge({ confidence }: Props) {
  const cls = confidence === "high" ? "badge--high"
            : confidence === "medium" ? "badge--medium"
            : "badge--low";
  return <span className={`badge ${cls}`}>{confidence.toUpperCase()}</span>;
}
