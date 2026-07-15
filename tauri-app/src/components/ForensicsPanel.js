import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useState, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
function fmtBytes(n) { if (n < 1024)
    return `${n} B`; if (n < 1024 * 1024)
    return `${(n / 1024).toFixed(1)} KB`; return `${(n / 1024 / 1024).toFixed(1)} MB`; }
function EntropyBar({ value }) {
    const pct = Math.min((value / 8) * 100, 100);
    const cls = value > 7.5 ? "ef--high" : value > 6.5 ? "ef--medium" : value > 4.0 ? "ef--normal" : "ef--low";
    return _jsx("div", { className: "entropy-track", children: _jsx("div", { className: `entropy-fill ${cls}`, style: { width: `${pct.toFixed(1)}%` } }) });
}
function ResultRow({ r }) {
    const [open, setOpen] = useState(false);
    const fname = r.path.split("/").pop() ?? r.path;
    return (_jsxs(_Fragment, { children: [_jsxs("div", { className: `result-row result-row--${r.risk}`, onClick: () => setOpen(v => !v), children: [_jsx("span", { className: "result-name", title: r.path, children: fname }), r.entropy != null ? _jsx(EntropyBar, { value: r.entropy }) : _jsx("div", { style: { flex: 1 } }), _jsx("span", { className: "entropy-val", children: r.entropy?.toFixed(3) ?? "—" }), _jsx("span", { className: "result-mime", children: r.mime_guess }), _jsx("span", { className: "result-size", children: fmtBytes(r.size_bytes) }), _jsx("span", { className: `risk-pill rp--${r.risk === "skipped" ? "skip" : r.risk}`, children: r.risk.toUpperCase() })] }), open && _jsxs("div", { className: "result-detail", children: [_jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "PATH" }), _jsx("code", { className: "meta-code", children: r.path })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "NOTE" }), _jsx("span", { className: "meta-val", children: r.note })] })] })] }));
}
export default function ForensicsPanel() {
    const [summary, setSummary] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [error, setError] = useState(null);
    const [dragOver, setDragOver] = useState(false);
    const [filter, setFilter] = useState("all");
    const inputRef = useRef(null);
    const runScan = useCallback(async (path) => {
        setScanning(true);
        setError(null);
        setSummary(null);
        try {
            const r = await invoke("scan_entropy", { request: { path, max_bytes: 33554432, recursive: true } });
            setSummary(r);
        }
        catch (e) {
            setError(String(e));
        }
        finally {
            setScanning(false);
        }
    }, []);
    const displayed = summary?.results.filter(r => filter === "all" ? true : r.risk === filter) ?? [];
    return (_jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-header", children: [_jsx("span", { className: "panel-title", children: "FILE FORENSICS \u2014 ENTROPY SCANNER" }), summary && _jsxs(_Fragment, { children: [_jsxs("span", { className: "pstat", children: [summary.scanned_files, " SCANNED"] }), summary.high_risk > 0 && _jsxs("span", { className: "pstat pstat--warn", children: ["\u26A0 ", summary.high_risk, " HIGH-RISK"] }), _jsxs("span", { className: "scan-time", children: [summary.elapsed_ms, "ms"] })] }), _jsxs("div", { className: "toolbar-right", children: [summary && _jsxs("select", { className: "filter-select", value: filter, onChange: e => setFilter(e.target.value), children: [_jsx("option", { value: "all", children: "ALL RESULTS" }), _jsx("option", { value: "high", children: "HIGH RISK" }), _jsx("option", { value: "medium", children: "MEDIUM RISK" }), _jsx("option", { value: "normal", children: "NORMAL" }), _jsx("option", { value: "skipped", children: "SKIPPED" })] }), _jsx("input", { ref: inputRef, type: "file", style: { display: "none" }, onChange: e => { const f = e.target.files?.[0]; if (f)
                                    runScan(f.path ?? f.name); } }), _jsx("button", { className: "sm-btn", onClick: () => inputRef.current?.click(), disabled: scanning, children: "BROWSE FILE\u2026" }), summary && _jsx("button", { className: "sm-btn", onClick: () => { setSummary(null); setFilter("all"); }, children: "NEW SCAN" })] })] }), !scanning && !summary && !error && (_jsxs("div", { className: `drop-zone ${dragOver ? "drop-zone--active" : ""}`, onDragOver: e => { e.preventDefault(); setDragOver(true); }, onDragLeave: () => setDragOver(false), onDrop: e => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f)
                    runScan(f.path ?? f.name); }, onClick: () => inputRef.current?.click(), children: [_jsx("div", { className: "drop-icon-box", children: "+" }), _jsx("div", { className: "drop-title", children: "DROP FILE OR DIRECTORY HERE" }), _jsx("div", { className: "drop-sub", children: "Shannon entropy analysis \u2014 packed binaries and encrypted blobs score near 8.0 bits/byte. No files are modified." }), _jsx("div", { className: "drop-sub drop-passive", children: "PASSIVE ANALYSIS ONLY" })] })), scanning && _jsxs("div", { className: "empty-state", children: [_jsx("div", { className: "spinner" }), _jsx("span", { children: "SCANNING\u2026" })] }), error && _jsxs("div", { className: "empty-state", style: { color: "var(--redl)" }, children: [_jsx("span", { className: "empty-icon", style: { color: "var(--red)" }, children: "\u2715" }), error] }), summary && !scanning && (_jsxs(_Fragment, { children: [_jsxs("div", { className: "scan-summary-bar", children: [_jsxs("div", { className: "sum-pill", children: [_jsx("span", { className: "sum-pill-val", children: summary.total_files }), _jsx("span", { className: "sum-pill-label", children: "TOTAL" })] }), _jsxs("div", { className: "sum-pill", children: [_jsx("span", { className: "sum-pill-val", children: summary.scanned_files }), _jsx("span", { className: "sum-pill-label", children: "SCANNED" })] }), _jsxs("div", { className: "sum-pill sum-pill--high", children: [_jsx("span", { className: "sum-pill-val", style: { color: "var(--redl)" }, children: summary.high_risk }), _jsx("span", { className: "sum-pill-label", children: "HIGH" })] }), _jsxs("div", { className: "sum-pill sum-pill--medium", children: [_jsx("span", { className: "sum-pill-val", style: { color: "var(--amberl)" }, children: summary.medium_risk }), _jsx("span", { className: "sum-pill-label", children: "MEDIUM" })] }), _jsxs("div", { className: "sum-pill", children: [_jsx("span", { className: "sum-pill-val", children: summary.skipped_files }), _jsx("span", { className: "sum-pill-label", children: "SKIPPED" })] })] }), _jsx("div", { className: "result-list", children: displayed.length === 0 ? _jsx("div", { className: "empty-state", children: "NO RESULTS MATCH FILTER" }) : displayed.map((r, i) => _jsx(ResultRow, { r: r }, i)) })] }))] }));
}
