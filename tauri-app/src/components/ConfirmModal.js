import { jsxs as _jsxs, jsx as _jsx } from "react/jsx-runtime";
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
const ACTION_META = {
    kill: { label: "KILL PROCESS", color: "var(--red)", icon: "✕", warning: "This will send SIGTERM then SIGKILL. The action is IRREVERSIBLE.", reversible: false },
    quarantine: { label: "QUARANTINE", color: "var(--amber)", icon: "⊘", warning: "This will isolate the process from the network. Files are not affected. Reversible via Lift Quarantine.", reversible: true },
    whitelist: { label: "WHITELIST", color: "var(--teal)", icon: "✓", warning: "This process will never be flagged or acted upon again, even if it triggers detection rules.", reversible: true },
};
export default function ConfirmModal({ incident, action, onClose, onSuccess }) {
    const [challenge, setChallenge] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const meta = ACTION_META[action];
    const expected = `CONFIRM-${action.toUpperCase()}-${incident.pid}`;
    const matches = challenge.trim() === expected;
    async function execute() {
        if (!matches)
            return;
        setLoading(true);
        setError(null);
        try {
            const result = await invoke("execute_action", {
                pid: incident.pid, processName: incident.process, exePath: incident.exe_path,
                action, incidentId: incident.id, challenge: challenge.trim(),
                note: `Action via dashboard — incident ${incident.id}`,
            });
            onSuccess(result.message);
            onClose();
        }
        catch (e) {
            setError(String(e));
        }
        finally {
            setLoading(false);
        }
    }
    return (_jsx("div", { className: "modal-backdrop", onClick: onClose, children: _jsxs("div", { className: "modal confirm-modal", onClick: e => e.stopPropagation(), children: [_jsxs("div", { className: "modal-header", style: { borderColor: meta.color }, children: [_jsxs("span", { className: "modal-proc-name", style: { color: meta.color }, children: [meta.icon, " ", meta.label] }), _jsx("button", { className: "modal-close", onClick: onClose, children: "\u2715" })] }), _jsxs("div", { className: "modal-section", children: [_jsx("div", { className: "modal-section-title", children: "TARGET PROCESS" }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "PROCESS" }), _jsx("span", { className: "meta-val", children: incident.process })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "PID" }), _jsx("span", { className: "meta-val", children: incident.pid })] }), _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "RULE" }), _jsx("span", { className: "meta-val", children: incident.rule })] }), incident.exe_path && _jsxs("div", { className: "meta-row", children: [_jsx("span", { className: "meta-label", children: "EXE" }), _jsx("code", { className: "meta-code", children: incident.exe_path })] })] }), _jsxs("div", { className: "modal-section", style: { borderLeft: `2px solid ${meta.color}`, background: `${meta.color}08` }, children: [_jsx("div", { className: "modal-section-title", style: { color: meta.color }, children: "\u26A0 WARNING" }), _jsx("p", { style: { fontSize: 11, color: "var(--tx1)", lineHeight: 1.6 }, children: meta.warning }), !meta.reversible && _jsx("p", { style: { fontSize: 11, color: "var(--redl)", marginTop: 6, fontWeight: 700 }, children: "THIS ACTION CANNOT BE UNDONE." })] }), _jsxs("div", { className: "modal-section", children: [_jsx("div", { className: "modal-section-title", children: "CONFIRMATION REQUIRED" }), _jsx("p", { style: { fontSize: 10, color: "var(--tx2)", marginBottom: 8 }, children: "Type the following token exactly to confirm:" }), _jsx("div", { className: "challenge-token", children: expected }), _jsx("input", { className: "challenge-input", placeholder: "Type token here\u2026", value: challenge, onChange: e => setChallenge(e.target.value), onKeyDown: e => { if (e.key === "Enter" && matches)
                                execute(); }, autoFocus: true, style: { borderColor: challenge ? (matches ? "var(--teal)" : "var(--red)") : "var(--border)" } }), challenge && !matches && _jsx("p", { style: { fontSize: 10, color: "var(--redl)", marginTop: 4 }, children: "TOKEN MISMATCH \u2014 type exactly as shown" }), matches && _jsx("p", { style: { fontSize: 10, color: "var(--teall)", marginTop: 4 }, children: "\u2713 TOKEN VERIFIED" })] }), error && _jsx("div", { style: { margin: "0 16px 8px", padding: "8px 10px", background: "var(--redd)", border: "1px solid var(--red)", borderRadius: 4, fontSize: 10, color: "var(--redl)" }, children: error }), _jsxs("div", { style: { display: "flex", gap: 8, padding: "12px 16px", justifyContent: "flex-end" }, children: [_jsx("button", { className: "sm-btn", onClick: onClose, disabled: loading, children: "CANCEL" }), _jsx("button", { disabled: !matches || loading, onClick: execute, style: { padding: "5px 16px", fontSize: 10, fontWeight: 700, letterSpacing: ".07em", border: `1px solid ${meta.color}`, borderRadius: 4,
                                background: matches ? `${meta.color}22` : "var(--bg3)", color: matches ? meta.color : "var(--tx2)",
                                cursor: matches ? "pointer" : "default", transition: "all 120ms", fontFamily: "var(--mono)" }, children: loading ? "EXECUTING…" : meta.label })] })] }) }));
}
