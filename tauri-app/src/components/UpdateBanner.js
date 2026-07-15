import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
export default function UpdateBanner() {
    const [info, setInfo] = useState(null);
    const [checking, setChecking] = useState(false);
    const [dismissed, setDismissed] = useState(false);
    useEffect(() => {
        const unsub = listen("update-available", ev => { setInfo(ev.payload); setDismissed(false); });
        return () => { unsub.then(f => f()); };
    }, []);
    async function checkNow() {
        setChecking(true);
        try {
            const r = await invoke("check_update");
            setInfo(r);
            if (!r.update_available)
                setTimeout(() => setInfo(null), 3000);
        }
        catch { /* network error — silent */ }
        finally {
            setChecking(false);
        }
    }
    if (info && !dismissed) {
        const cls = info.update_available ? "" : "update-banner--ok";
        return (_jsxs("div", { className: `update-banner ${cls}`, children: [_jsx("span", { className: "update-msg", children: info.update_available ? `↑ UPDATE AVAILABLE — v${info.latest_version}` : `✓ AEGIS-GUARD IS UP TO DATE (v${info.current_version})` }), info.update_available && _jsx("a", { className: "update-link", href: info.release_url, target: "_blank", rel: "noreferrer", children: "RELEASE NOTES" }), _jsx("button", { onClick: () => setDismissed(true), style: { marginLeft: "auto", background: "none", border: "none", color: "var(--vl)", cursor: "pointer", fontFamily: "var(--mono)", fontSize: 10 }, children: "\u2715" })] }));
    }
    return _jsx("button", { className: "check-update-btn", onClick: checkNow, disabled: checking, children: checking ? "CHECKING…" : "CHECK FOR UPDATES" });
}
