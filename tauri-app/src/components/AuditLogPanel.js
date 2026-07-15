import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
export default function AuditLogPanel() {
    const [entries, setEntries] = useState([]);
    const [chainOk, setChainOk] = useState(null);
    const [chainErrs, setChainErrs] = useState([]);
    const [verifying, setVerifying] = useState(false);
    useEffect(() => { invoke("list_audit_log", { limit: 100, offset: 0 }).then(setEntries).catch(console.error); }, []);
    async function verifyChain() {
        setVerifying(true);
        try {
            const errs = await invoke("verify_audit_chain");
            setChainErrs(errs);
            setChainOk(errs.length === 0);
        }
        catch (e) {
            setChainOk(false);
            setChainErrs([String(e)]);
        }
        finally {
            setVerifying(false);
        }
    }
    const statusColor = (s) => s === "success" ? "var(--teall)" : s === "failed" ? "var(--redl)" : "var(--amberl)";
    return (_jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-header", children: [_jsx("span", { className: "panel-title", children: "AUDIT LOG \u2014 ACTIVE DEFENSE ACTIONS" }), _jsxs("span", { className: "pstat", children: [entries.length, " ENTRIES"] }), chainOk === true && _jsx("span", { className: "pstat", style: { borderColor: "var(--teal)", color: "var(--teall)" }, children: "\u2713 CHAIN INTACT" }), chainOk === false && _jsx("span", { className: "pstat pstat--warn", children: "\u26A0 CHAIN BROKEN" }), _jsx("div", { className: "toolbar-right", children: _jsx("button", { className: "sm-btn", onClick: verifyChain, disabled: verifying, children: verifying ? "VERIFYING…" : "VERIFY CHAIN" }) })] }), chainErrs.length > 0 && _jsx("div", { style: { margin: "8px 14px", padding: "8px 12px", background: "var(--redd)", border: "1px solid var(--red)", borderRadius: 4, fontSize: 10, color: "var(--redl)" }, children: chainErrs.map((e, i) => _jsx("div", { children: e }, i)) }), _jsxs("div", { style: { display: "grid", gridTemplateColumns: "80px 110px 60px 80px 1fr 70px", padding: "4px 14px", fontSize: 9, color: "var(--tx2)", letterSpacing: ".08em", textTransform: "uppercase", borderBottom: "1px solid var(--border)", background: "var(--bg1)", flexShrink: 0 }, children: [_jsx("span", { children: "ACTION" }), _jsx("span", { children: "PROCESS" }), _jsx("span", { children: "PID" }), _jsx("span", { children: "STATUS" }), _jsx("span", { children: "OUTCOME" }), _jsx("span", { children: "TIME" })] }), _jsx("div", { style: { flex: 1, overflowY: "auto" }, children: entries.length === 0 ? _jsxs("div", { className: "empty-state", children: [_jsx("span", { className: "empty-icon", children: "\u25C8" }), "NO ACTIVE DEFENSE ACTIONS YET"] }) : entries.map(e => (_jsxs("div", { style: { display: "grid", gridTemplateColumns: "80px 110px 60px 80px 1fr 70px", padding: "5px 14px", borderBottom: "1px solid rgba(37,37,50,.45)", alignItems: "center", gap: 8, fontSize: 10 }, children: [_jsx("span", { style: { fontFamily: "var(--mono)", fontSize: 9, color: e.action === "Kill" ? "var(--redl)" : e.action === "Quarantine" ? "var(--amberl)" : "var(--teall)" }, children: e.action.toUpperCase() }), _jsx("span", { style: { fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }, children: e.process }), _jsx("span", { style: { color: "var(--tx2)", fontFamily: "var(--mono)" }, children: e.pid }), _jsx("span", { style: { color: statusColor(e.status), fontSize: 9, fontWeight: 700, letterSpacing: ".05em" }, children: e.status.toUpperCase() }), _jsx("span", { style: { color: "var(--tx2)", fontSize: 9, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }, children: e.outcome ?? "—" }), _jsx("span", { style: { color: "var(--tx2)", fontSize: 9, fontFamily: "var(--mono)", whiteSpace: "nowrap" }, children: new Date(e.ts_before).toLocaleTimeString("en-GB", { hour12: false }) })] }, e.id))) })] }));
}
