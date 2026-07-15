import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useProcessStore } from "../store/processStore";
import UpdateBanner from "./UpdateBanner";
const NAV = [
    { id: "processes", icon: "⬡", label: "PROCESSES" },
    { id: "journal", icon: "◈", label: "JOURNAL" },
    { id: "forensics", icon: "⊕", label: "FORENSICS" },
    { id: "debug", icon: "⊘", label: "DEBUG LOG" },
    { id: "audit", icon: "⬟", label: "AUDIT LOG" },
    { id: "intel", icon: "◉", label: "THREAT INTEL" },
    { id: "canary", icon: "⟡", label: "CANARY" },
];
export default function Sidebar({ active, setActive }) {
    const { store } = useProcessStore();
    const connected = store.nodes.size > 0;
    return (_jsxs("nav", { className: "sidebar", children: [_jsxs("div", { className: "sidebar-brand", children: [_jsx("div", { className: "brand-hex" }), _jsx("div", { className: "brand-name", children: "AEGIS-GUARD" }), _jsx("div", { className: "brand-sub", children: "ENDPOINT SECURITY SUITE" }), _jsx("div", { className: "brand-author", children: "BY VLADIMIR UNKNOWN" })] }), _jsx("ul", { className: "sidebar-nav", children: NAV.map(({ id, icon, label }) => (_jsx("li", { children: _jsxs("div", { className: `nav-item ${active === id ? "nav-item--active" : ""}`, onClick: () => setActive(id), children: [_jsx("span", { className: "nav-icon", children: icon }), _jsx("span", { className: "nav-label", children: label }), id === "journal" && store.openCount > 0 && _jsx("span", { className: "nav-badge", children: store.openCount })] }) }, id))) }), _jsxs("div", { className: "sidebar-footer", children: [_jsxs("div", { className: `engine-status ${connected ? "status--live" : "status--wait"}`, children: [_jsx("span", { className: "status-dot" }), _jsx("span", { className: "status-label", children: connected ? `ENGINE LIVE · ${store.nodes.size} PROCS` : "WAITING FOR ENGINE…" })] }), _jsx("div", { className: "phase-tag", children: "FULL STACK \u00B7 LINUX" }), _jsx(UpdateBanner, {})] })] }));
}
