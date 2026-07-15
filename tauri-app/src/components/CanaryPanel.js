import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
export default function CanaryPanel() {
    const [tokens, setTokens] = useState([]);
    const [filePath, setFilePath] = useState("");
    const [desc, setDesc] = useState("");
    const [creating, setCreating] = useState(false);
    const [error, setError] = useState(null);
    async function load() { try {
        setTokens(await invoke("list_canaries"));
    }
    catch (e) {
        console.error(e);
    } }
    useEffect(() => { load(); }, []);
    async function create() {
        if (!filePath.trim())
            return;
        setCreating(true);
        setError(null);
        try {
            await invoke("create_canary", { filePath: filePath.trim(), description: desc.trim() });
            setFilePath("");
            setDesc("");
            await load();
        }
        catch (e) {
            setError(String(e));
        }
        finally {
            setCreating(false);
        }
    }
    async function remove(id) { try {
        await invoke("delete_canary", { id });
        await load();
    }
    catch (e) {
        console.error(e);
    } }
    return (_jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-header", children: [_jsx("span", { className: "panel-title", children: "CANARY TOKENS" }), _jsxs("span", { className: "pstat", children: [tokens.length, " ACTIVE"] }), tokens.some(t => t.triggered) && _jsxs("span", { className: "pstat pstat--warn", children: ["\u26A0 ", tokens.filter(t => t.triggered).length, " TRIGGERED"] })] }), _jsxs("div", { style: { padding: "14px 16px", borderBottom: "1px solid var(--border)", display: "flex", flexDirection: "column", gap: 8 }, children: [_jsx("div", { style: { fontSize: 9, color: "var(--tx2)", letterSpacing: ".1em", textTransform: "uppercase" }, children: "Embed Canary Token in File" }), _jsx("div", { style: { fontSize: 10, color: "var(--tx2)", lineHeight: 1.6 }, children: "A unique token is embedded in your file as a comment. If this token appears in outbound network traffic, data exfiltration is detected." }), _jsx("input", { className: "search-input", style: { width: "100%" }, placeholder: "File path \u2014 e.g. /home/user/.ssh/config", value: filePath, onChange: e => setFilePath(e.target.value) }), _jsx("input", { className: "search-input", style: { width: "100%" }, placeholder: "Description \u2014 e.g. SSH config canary", value: desc, onChange: e => setDesc(e.target.value) }), error && _jsx("div", { style: { fontSize: 10, color: "var(--redl)" }, children: error }), _jsx("button", { className: "action-btn", style: { width: "fit-content" }, onClick: create, disabled: creating || !filePath.trim(), children: creating ? "CREATING…" : "CREATE CANARY TOKEN" })] }), _jsx("div", { style: { flex: 1, overflowY: "auto" }, children: tokens.length === 0 ? _jsxs("div", { className: "empty-state", children: [_jsx("span", { className: "empty-icon", children: "\u2B1F" }), "NO CANARY TOKENS \u2014 create one above"] }) : tokens.map(t => (_jsxs("div", { style: { padding: "10px 16px", borderBottom: "1px solid var(--border)", borderLeft: `2px solid ${t.triggered ? "var(--red)" : "var(--teal)"}`, display: "flex", flexDirection: "column", gap: 5 }, children: [_jsxs("div", { style: { display: "flex", alignItems: "center", gap: 8 }, children: [_jsx("span", { style: { fontSize: 9, fontWeight: 700, color: t.triggered ? "var(--redl)" : "var(--teall)", padding: "1px 6px", border: `1px solid ${t.triggered ? "rgba(220,38,38,.4)" : "rgba(13,148,136,.4)"}`, borderRadius: 2 }, children: t.triggered ? "⚠ TRIGGERED" : "ACTIVE" }), _jsx("span", { style: { flex: 1, fontSize: 11, color: "var(--tx0)", fontWeight: 600 }, children: t.description || t.file_path }), _jsx("button", { className: "sm-btn", style: { fontSize: 9 }, onClick: () => remove(t.id), children: "REMOVE" })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "FILE" }), _jsx("code", { className: "meta-code", children: t.file_path })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "TOKEN" }), _jsxs("code", { className: "meta-code", style: { color: "var(--tx2)", fontSize: 9 }, children: [t.token.slice(0, 20), "\u2026"] })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "CREATED" }), _jsx("span", { className: "meta-val", children: new Date(t.created_ts).toLocaleString("en-GB") })] })] }, t.id))) })] }));
}
