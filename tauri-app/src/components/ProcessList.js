import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useMemo } from "react";
import { useProcessStore } from "../store/processStore";
import ProcessRow from "./ProcessRow";
export default function ProcessList() {
    const { store } = useProcessStore();
    const [filter, setFilter] = useState("");
    const [anomOnly, setAnomOnly] = useState(false);
    const roots = useMemo(() => {
        const all = Array.from(store.nodes.values());
        const pids = new Set(all.map(n => n.pid));
        let top = all.filter(n => !pids.has(n.ppid));
        top.sort((a, b) => (a.flagged ? -1 : 0) - (b.flagged ? -1 : 0) || a.pid - b.pid);
        if (filter.trim()) {
            const q = filter.toLowerCase();
            const match = (n) => n.name.toLowerCase().includes(q) || n.cmdline.join(" ").toLowerCase().includes(q) || String(n.pid).includes(q);
            top = top.filter(match);
        }
        if (anomOnly) {
            const has = (n) => n.flagged || n.children.some(has);
            top = top.filter(has);
        }
        return top;
    }, [store.nodes, filter, anomOnly]);
    return (_jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-header", children: [_jsx("span", { className: "panel-title", children: "LIVE PROCESS MONITOR" }), _jsxs("span", { className: "pstat", children: [store.nodes.size, " RUNNING"] }), store.anomalies.length > 0 && _jsxs("span", { className: "pstat pstat--warn", children: ["\u26A0 ", store.anomalies.length, " FLAGGED"] }), _jsxs("div", { className: "toolbar-right", children: [_jsx("input", { className: "search-input", placeholder: "Search name / PID / args\u2026", value: filter, onChange: e => setFilter(e.target.value) }), _jsx("button", { className: `sm-btn ${anomOnly ? "sm-btn--active" : ""}`, onClick: () => setAnomOnly(v => !v), children: "ANOMALIES ONLY" })] })] }), _jsxs("div", { className: "proc-cols", children: [_jsx("span", { children: "NAME" }), _jsx("span", { children: "PID" }), _jsx("span", { children: "PPID" }), _jsx("span", { children: "UID" }), _jsx("span", { children: "STATUS" })] }), _jsx("div", { className: "proc-tree", children: roots.length === 0 ? (_jsxs("div", { className: "empty-state", children: [_jsx("span", { className: "empty-icon", children: "\u2B21" }), store.nodes.size === 0 ? "WAITING FOR PROCESS ENGINE…" : "NO MATCHES FOR CURRENT FILTER"] })) : roots.map(n => _jsx(ProcessRow, { node: n, depth: 0 }, n.pid)) })] }));
}
