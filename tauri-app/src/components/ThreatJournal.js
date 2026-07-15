import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import ConfidenceBadge from "./ConfidenceBadge";
import RuleBadge from "./RuleBadge";
const PAGE = 50;
export default function ThreatJournal() {
    const [incidents, setIncidents] = useState([]);
    const [offset, setOffset] = useState(0);
    const [expanded, setExpanded] = useState(null);
    const [cat, setCat] = useState("all");
    const [exporting, setExporting] = useState(false);
    const load = useCallback(async (off) => {
        const rows = await invoke("list_incidents", { limit: PAGE, offset: off });
        setIncidents(prev => off === 0 ? rows : [...prev, ...rows]);
        setOffset(off + rows.length);
    }, []);
    useEffect(() => { load(0); }, [load]);
    useEffect(() => { const u = listen("anomaly", () => load(0)); return () => { u.then(f => f()); }; }, [load]);
    async function resolve(id) {
        await invoke("resolve_incident", { id });
        setIncidents(prev => prev.map(i => i.id === id ? { ...i, resolved: true } : i));
    }
    async function doExport(fmt) {
        setExporting(true);
        const data = fmt === "markdown" ? await invoke("export_markdown") : await invoke("export_json");
        const mime = fmt === "markdown" ? "text/markdown" : "application/json";
        const ext = fmt === "markdown" ? "md" : "json";
        const blob = new Blob([data], { type: mime });
        const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `aegis-report-${Date.now()}.${ext}` });
        a.click();
        setExporting(false);
    }
    const counts = { all: incidents.length };
    ["PAR", "PATH", "ARG", "ENV"].forEach(c => { counts[c] = incidents.filter(i => i.rule.startsWith(c)).length; });
    const filtered = incidents.filter(i => cat === "all" || i.rule.startsWith(cat));
    const open = filtered.filter(i => !i.resolved);
    const closed = filtered.filter(i => i.resolved);
    return (_jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-header", children: [_jsx("span", { className: "panel-title", children: "THREAT JOURNAL" }), open.length > 0 && _jsxs("span", { className: "pstat pstat--warn", children: [open.length, " OPEN"] }), _jsxs("div", { className: "toolbar-right", children: [_jsx("button", { className: "sm-btn", onClick: () => doExport("markdown"), disabled: exporting || !incidents.length, children: "EXPORT .MD" }), _jsx("button", { className: "sm-btn", onClick: () => doExport("json"), disabled: exporting || !incidents.length, children: "EXPORT .JSON" })] })] }), _jsx("div", { className: "cat-tabs", children: ["all", "PAR", "PATH", "ARG", "ENV"].map(c => (_jsxs("div", { className: `cat-tab ${cat === c ? "cat-tab--active" : ""}`, onClick: () => setCat(c), children: [c.toUpperCase(), counts[c] > 0 && _jsx("span", { className: "cat-tab-count", children: counts[c] })] }, c))) }), _jsx("div", { className: "journal-list", children: filtered.length === 0 ? (_jsxs("div", { className: "empty-state", children: [_jsx("span", { className: "empty-icon", children: "\u25C8" }), "NO INCIDENTS IN THIS CATEGORY"] })) : (_jsxs(_Fragment, { children: [open.map(inc => _jsx(IncCard, { inc: inc, expanded: expanded === inc.id, onToggle: () => setExpanded(v => v === inc.id ? null : inc.id), onResolve: () => resolve(inc.id) }, inc.id)), closed.length > 0 && (_jsxs(_Fragment, { children: [_jsxs("div", { className: "section-divider", children: ["RESOLVED (", closed.length, ")"] }), closed.map(inc => _jsx(IncCard, { inc: inc, expanded: expanded === inc.id, onToggle: () => setExpanded(v => v === inc.id ? null : inc.id), onResolve: () => { } }, inc.id))] })), incidents.length >= PAGE && _jsx("button", { className: "load-more", onClick: () => load(offset), children: "LOAD MORE" })] })) })] }));
}
function IncCard({ inc, expanded, onToggle, onResolve }) {
    const cls = `incident-card incident-card--${inc.severity}${inc.resolved ? " incident-card--resolved" : ""}`;
    const ts = new Date(inc.ts).toLocaleTimeString("en-GB", { hour12: false });
    return (_jsxs("div", { className: cls, children: [_jsxs("div", { className: "card-summary", onClick: onToggle, children: [_jsxs("div", { className: "card-left", children: [_jsx(RuleBadge, { rule: inc.rule }), _jsx("span", { className: "card-process", children: inc.process }), _jsx(ConfidenceBadge, { confidence: inc.confidence })] }), _jsxs("div", { className: "card-right", children: [_jsx("span", { className: "card-ts", children: ts }), !inc.resolved && _jsx("button", { className: "resolve-btn", onClick: e => { e.stopPropagation(); onResolve(); }, children: "DISMISS" }), _jsx("span", { className: "card-chevron", children: expanded ? "▲" : "▼" })] })] }), expanded && (_jsxs("div", { className: "card-detail", children: [_jsx("div", { className: "card-reason", children: inc.reason }), inc.exe_path && _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "EXE" }), _jsx("code", { className: `meta-code ${inc.exe_path.endsWith("(deleted)") ? "meta-code--danger" : ""}`, children: inc.exe_path })] }), inc.cmdline.length > 0 && _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "CMDLINE" }), _jsx("code", { className: "meta-code", children: inc.cmdline.join(" ") })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "KIND" }), _jsx("span", { className: "meta-val", children: inc.kind.replace(/_/g, " ").toUpperCase() })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "PID / PPID" }), _jsxs("span", { className: "meta-val", children: [inc.pid, " / ", inc.ppid] })] }), inc.ancestors.length > 0 && _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "ANCESTORS" }), _jsx("span", { className: "meta-val", children: inc.ancestors.join(" → ") })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "DIGEST" }), _jsxs("code", { className: "meta-code meta-code--muted", children: [inc.digest.slice(0, 24), "\u2026"] })] })] }))] }));
}
