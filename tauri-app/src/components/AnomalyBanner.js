import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import RuleBadge from "./RuleBadge";
export default function AnomalyBanner() {
    const [alerts, setAlerts] = useState([]);
    useEffect(() => {
        const unsub = listen("anomaly", ev => {
            const inc = ev.payload;
            setAlerts(prev => [inc, ...prev].slice(0, 5));
            setTimeout(() => setAlerts(p => p.filter(a => a.id !== inc.id)), 9000);
        });
        return () => { unsub.then(f => f()); };
    }, []);
    if (!alerts.length)
        return null;
    return (_jsx("div", { className: "banner-stack", children: alerts.map(inc => (_jsxs("div", { className: `alert-banner ${inc.severity === "high" ? "ab--high" : "ab--medium"}`, children: [_jsx(RuleBadge, { rule: inc.rule }), _jsxs("span", { className: "ab-msg", children: [_jsx("strong", { children: inc.process }), " \u2014 ", inc.reason.slice(0, 90), inc.reason.length > 90 ? "…" : ""] }), _jsx("button", { className: "ab-close", onClick: () => setAlerts(p => p.filter(a => a.id !== inc.id)), children: "\u2715" })] }, inc.id))) }));
}
