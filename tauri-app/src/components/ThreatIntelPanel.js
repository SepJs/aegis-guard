import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
export default function ThreatIntelPanel() {
    const [stats, setStats] = useState(null);
    const [query, setQuery] = useState("");
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    useEffect(() => { invoke("get_ioc_stats").then(setStats).catch(console.error); }, []);
    async function lookup() {
        if (!query.trim())
            return;
        setLoading(true);
        setResult(null);
        try {
            const r = await invoke("check_ioc_manual", { value: query.trim(), context: "manual-lookup" });
            setResult(r ?? "clean");
        }
        catch (e) {
            console.error(e);
        }
        finally {
            setLoading(false);
        }
    }
    return (_jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-header", children: [_jsx("span", { className: "panel-title", children: "THREAT INTELLIGENCE" }), stats && _jsxs(_Fragment, { children: [_jsxs("span", { className: "pstat", children: [stats.ips + stats.cidrs, " IPs/CIDRs"] }), _jsxs("span", { className: "pstat", children: [stats.domains, " DOMAINS"] }), _jsxs("span", { className: "pstat", children: [stats.hashes, " HASHES"] })] }), _jsx("div", { className: "toolbar-right", children: _jsx("span", { style: { fontSize: 9, color: "var(--tx2)", letterSpacing: ".06em" }, children: "FEEDS: BUNDLED + URLHAUS (6h refresh)" }) })] }), _jsxs("div", { style: { padding: "14px 16px", borderBottom: "1px solid var(--border)" }, children: [_jsx("div", { style: { fontSize: 9, color: "var(--tx2)", letterSpacing: ".1em", marginBottom: 8, textTransform: "uppercase" }, children: "Manual IOC Lookup" }), _jsxs("div", { style: { display: "flex", gap: 8 }, children: [_jsx("input", { className: "search-input", style: { flex: 1, width: "auto" }, placeholder: "IP address, domain, MD5 or SHA256 hash\u2026", value: query, onChange: e => setQuery(e.target.value), onKeyDown: e => { if (e.key === "Enter")
                                    lookup(); } }), _jsx("button", { className: "action-btn", onClick: lookup, disabled: loading || !query.trim(), children: loading ? "CHECKING…" : "CHECK" })] }), result && (_jsx("div", { style: { marginTop: 10, padding: "10px 12px", borderRadius: 4, border: `1px solid ${result === "clean" ? "var(--teal)" : "var(--red)"}`, background: result === "clean" ? "rgba(13,148,136,.08)" : "rgba(220,38,38,.08)" }, children: result === "clean" ? (_jsx("div", { style: { fontSize: 11, color: "var(--teall)" }, children: "\u2713 No matches found in threat intelligence feeds \u2014 IOC appears clean." })) : (_jsxs("div", { style: { display: "flex", flexDirection: "column", gap: 5 }, children: [_jsxs("div", { style: { fontSize: 11, fontWeight: 700, color: "var(--redl)" }, children: ["\u26A0 IOC MATCHED \u2014 ", result.threat_type.toUpperCase()] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "IOC" }), _jsx("code", { className: "meta-code", children: result.ioc })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "TYPE" }), _jsx("span", { className: "meta-val", children: result.kind })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "THREAT" }), _jsx("span", { className: "meta-val", style: { color: "var(--redl)" }, children: result.threat_type })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "FEED" }), _jsx("span", { className: "meta-val", children: result.feed })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "CONFIDENCE" }), _jsxs("span", { className: "meta-val", children: [result.confidence, "%"] })] })] })) }))] }), _jsxs("div", { style: { padding: "14px 16px", flex: 1, overflow: "auto" }, children: [_jsx("div", { style: { fontSize: 9, color: "var(--tx2)", letterSpacing: ".1em", marginBottom: 10, textTransform: "uppercase" }, children: "Active Feeds" }), [{ name: "Bundled IOC Feed", entries: stats ? stats.ips + stats.domains + stats.hashes : "…", update: "Ships with binary" },
                        { name: "Abuse.ch URLhaus", entries: "500+", update: "Every 6 hours" },
                        { name: "Custom IOCs", entries: "—", update: "/var/lib/aegis/custom_iocs.json" }].map(feed => (_jsxs("div", { style: { display: "flex", alignItems: "center", gap: 12, padding: "8px 0", borderBottom: "1px solid var(--border-dim)" }, children: [_jsx("span", { style: { width: 6, height: 6, borderRadius: "50%", background: "var(--teall)", flexShrink: 0, boxShadow: "0 0 5px var(--teal)" } }), _jsx("span", { style: { flex: 1, fontSize: 11, color: "var(--tx0)" }, children: feed.name }), _jsxs("span", { style: { fontSize: 9, color: "var(--tx2)" }, children: [feed.entries, " entries"] }), _jsx("span", { style: { fontSize: 9, color: "var(--tx2)", fontStyle: "italic" }, children: feed.update })] }, feed.name)))] })] }));
}
