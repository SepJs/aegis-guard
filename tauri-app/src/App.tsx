import { useState, useReducer } from "react";
import Sidebar, { View } from "./components/Sidebar";
import ProcessList from "./components/ProcessList";
import TelemetryLogPanel from "./components/TelemetryLogPanel";
import ThreatJournal from "./components/ThreatJournal";
import ForensicsPanel from "./components/ForensicsPanel";
import DebugLogPanel from "./components/DebugLogPanel";
import AuditLogPanel from "./components/AuditLogPanel";
import ThreatIntelPanel from "./components/ThreatIntelPanel";
import CanaryPanel from "./components/CanaryPanel";
import NetworkObserverPanel from "./components/NetworkObserverPanel";
import SandboxPanel from "./components/SandboxPanel";
import AnomalyBanner from "./components/AnomalyBanner";
import InstallModal from "./components/InstallModal";
import SettingsPanel from "./components/SettingsPanel";
import { ProcessStoreContext, processReducer, initialStore, useProcessStore } from "./store/processStore";
import { useIpc } from "./hooks/useIpc";

function Clock() {
  const [t, setT] = useState(new Date());
  useState(() => { const id = setInterval(() => setT(new Date()), 1000); return () => clearInterval(id); });
  return <>{t.toLocaleTimeString("en-GB", { hour12: false })} UTC</>;
}

function AppShell() {
  const [view, setView] = useState<View>("processes");
  const [showInstallModal, setShowInstallModal] = useState(false);
  const { store } = useProcessStore();
  useIpc();

  return (
    <div className="app-shell">
      <Sidebar active={view} setActive={setView} />
      <div className="app-main">
        <div className="topbar">
          <span className="topbar-id">AEGIS-GUARD // ACTIVE ENDPOINT & NETWORK DEFENSE // <Clock /></span>
          <div className="tb-stat">PROCS <span>{store.nodes.size}</span></div>
          <div className="tb-stat">THREATS <span style={{ color: "var(--redl)" }}>{store.openCount}</span></div>
          <div className="tb-stat" style={{ borderLeft: "1px solid var(--vd)" }}>DEFENSE <span style={{ color: "var(--teall)" }}>ACTIVE</span></div>
          <button
            id="btn-open-install-modal"
            className="sm-btn"
            onClick={() => setShowInstallModal(true)}
            style={{
              marginLeft: "auto",
              background: "rgba(13,148,136,0.18)",
              color: "var(--teall)",
              borderColor: "var(--teal)",
              fontWeight: 700,
              fontSize: 11,
              letterSpacing: "0.05em",
              padding: "4px 12px",
              cursor: "pointer",
            }}
          >
            ⚡ 1-CLICK NATIVE INSTALL
          </button>
        </div>
        <AnomalyBanner />
        {showInstallModal && <InstallModal onClose={() => setShowInstallModal(false)} />}
        {view === "processes" && <ProcessList />}
        {view === "telemetry" && <TelemetryLogPanel />}
        {view === "network" && <NetworkObserverPanel />}
        {view === "sandbox" && <SandboxPanel />}
        {view === "journal" && <ThreatJournal />}
        {view === "forensics" && <ForensicsPanel />}
        {view === "debug" && <DebugLogPanel />}
        {view === "audit" && <AuditLogPanel />}
        {view === "intel" && <ThreatIntelPanel />}
        {view === "canary" && <CanaryPanel />}
        {view === "settings" && <SettingsPanel />}
      </div>
    </div>
  );
}


export default function App() {
  const [store, dispatch] = useReducer(processReducer, initialStore);
  return <ProcessStoreContext.Provider value={{ store, dispatch }}><AppShell /></ProcessStoreContext.Provider>;
}
