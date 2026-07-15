import { Fragment as _Fragment, jsxs as _jsxs, jsx as _jsx } from "react/jsx-runtime";
import { useState, useReducer } from "react";
import Sidebar from "./components/Sidebar";
import ProcessList from "./components/ProcessList";
import ThreatJournal from "./components/ThreatJournal";
import ForensicsPanel from "./components/ForensicsPanel";
import DebugLogPanel from "./components/DebugLogPanel";
import AuditLogPanel from "./components/AuditLogPanel";
import ThreatIntelPanel from "./components/ThreatIntelPanel";
import CanaryPanel from "./components/CanaryPanel";
import AnomalyBanner from "./components/AnomalyBanner";
import { ProcessStoreContext, processReducer, initialStore, useProcessStore } from "./store/processStore";
import { useIpc } from "./hooks/useIpc";
function Clock() {
    const [t, setT] = useState(new Date());
    useState(() => { const id = setInterval(() => setT(new Date()), 1000); return () => clearInterval(id); });
    return _jsxs(_Fragment, { children: [t.toLocaleTimeString("en-GB", { hour12: false }), " UTC"] });
}
function AppShell() {
    const [view, setView] = useState("processes");
    const { store } = useProcessStore();
    useIpc();
    return (_jsxs("div", { className: "app-shell", children: [_jsx(Sidebar, { active: view, setActive: setView }), _jsxs("div", { className: "app-main", children: [_jsxs("div", { className: "topbar", children: [_jsxs("span", { className: "topbar-id", children: ["AEGIS-GUARD // VLADIMIR UNKNOWN // ", _jsx(Clock, {})] }), _jsxs("div", { className: "tb-stat", children: ["PROCS ", _jsx("span", { children: store.nodes.size })] }), _jsxs("div", { className: "tb-stat", children: ["THREATS ", _jsx("span", { style: { color: "var(--redl)" }, children: store.openCount })] })] }), _jsx(AnomalyBanner, {}), view === "processes" && _jsx(ProcessList, {}), view === "journal" && _jsx(ThreatJournal, {}), view === "forensics" && _jsx(ForensicsPanel, {}), view === "debug" && _jsx(DebugLogPanel, {}), view === "audit" && _jsx(AuditLogPanel, {}), view === "intel" && _jsx(ThreatIntelPanel, {}), view === "canary" && _jsx(CanaryPanel, {})] })] }));
}
export default function App() {
    const [store, dispatch] = useReducer(processReducer, initialStore);
    return _jsx(ProcessStoreContext.Provider, { value: { store, dispatch }, children: _jsx(AppShell, {}) });
}
