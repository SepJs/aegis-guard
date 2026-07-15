import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import RuleBadge from "./RuleBadge";
export default function DebugLogPanel() {
    const [entries, setEntries] = useState([]);
    const [offset, setOffset] = useState(0);
    const PAGE = 50;
    async function load(off) {
        const rows = await invoke("list_debug_log", { limit: PAGE, offset: off });
        setEntries(prev => off === 0 ? rows : [...prev, ...rows]);
        setOffset(off + rows.length);
    }
    useEffect(() => { load(0); }, []);
    return (_jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-header", children: [_jsx("span", { className: "panel-title", children: "DEBUG LOG \u2014 FALSE POSITIVES" }), _jsxs("span", { className: "pstat", children: [entries.length, " ENTRIES"] }), _jsx("div", { className: "toolbar-right", children: _jsx("span", { style: { fontSize: 9, color: "var(--tx2)", letterSpacing: ".06em" }, children: "BENIGN EVENTS THAT TRIGGERED DETECTION RULES" }) })] }), _jsxs("div", { className: "debug-cols", children: [_jsx("span", { children: "RULE" }), _jsx("span", { children: "PROCESS" }), _jsx("span", { children: "PID" }), _jsx("span", { children: "NOTE" }), _jsx("span", { children: "TIME" })] }), _jsxs("div", { className: "debug-list", children: [entries.length === 0 ? (_jsxs("div", { className: "empty-state", children: [_jsx("span", { className: "empty-icon", children: "\u2298" }), "NO DEBUG ENTRIES YET"] })) : entries.map(e => (_jsxs("div", { className: "debug-row", children: [_jsx("span", { className: "debug-rule", children: _jsx(RuleBadge, { rule: e.rule }) }), _jsx("span", { className: "debug-process", children: e.process }), _jsxs("span", { className: "debug-pid", children: ["PID ", e.pid] }), _jsx("span", { className: "debug-note", children: e.note }), _jsx("span", { className: "debug-ts", children: new Date(e.ts).toLocaleTimeString("en-GB", { hour12: false }) })] }, e.id))), entries.length >= PAGE && _jsx("button", { className: "load-more", onClick: () => load(offset), children: "LOAD MORE" })] })] }));
}
