import { jsx as _jsx } from "react/jsx-runtime";
export default function ConfidenceBadge({ confidence }) {
    const cls = confidence === "high" ? "badge--high" : confidence === "medium" ? "badge--medium" : "badge--low";
    return _jsx("span", { className: `badge ${cls}`, children: confidence.toUpperCase() });
}
