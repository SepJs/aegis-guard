import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useState } from "react";
import ConfidenceBadge from "./ConfidenceBadge";
import RuleBadge from "./RuleBadge";
import DrillDownModal from "./DrillDownModal";
export default function ProcessRow({ node, depth }) {
    const [open, setOpen] = useState(false);
    const [exp, setExp] = useState(true);
    const has = node.children.length > 0;
    const rowCls = node.flagged
        ? node.anomaly?.confidence === "high" ? "proc-row proc-row--high"
            : node.anomaly?.confidence === "medium" ? "proc-row proc-row--medium" : "proc-row proc-row--low"
        : "proc-row";
    return (_jsxs(_Fragment, { children: [_jsxs("div", { className: rowCls, style: { paddingLeft: 12 + depth * 18 }, onClick: () => setOpen(true), children: [_jsxs("div", { className: "proc-name-cell", children: [has ? _jsx("button", { className: "chevron", onClick: e => { e.stopPropagation(); setExp(v => !v); }, children: exp ? "▾" : "▸" }) : _jsx("span", { className: "chevron-sp" }), _jsx("span", { className: "pname", children: node.name })] }), _jsx("span", { className: "pid-v", children: node.pid }), _jsx("span", { className: "ppid-v", children: node.ppid }), _jsx("span", { className: "uid-v", children: node.uid }), _jsxs("div", { className: "status-cell", children: [node.anomaly && _jsx(ConfidenceBadge, { confidence: node.anomaly.confidence }), node.anomaly && _jsx(RuleBadge, { rule: node.anomaly.rule })] })] }), exp && node.children.map(c => _jsx(ProcessRow, { node: c, depth: depth + 1 }, c.pid)), open && _jsx(DrillDownModal, { node: node, onClose: () => setOpen(false) })] }));
}
