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
  useState(() => {
    const id = setInterval(() => setT(new Date()), 1000);
    return () => clearInterval(id);
  });
  return <span className="topbar-time">{t.toLocaleTimeString("en-GB", { hour12: false })} UTC</span>;
}

function AppShell() {
  const [view, setView] = useState<View>("processes");
  const [showInstallModal, setShowInstallModal] = useState(false);
  const { store } = useProcessStore();
  useIpc();

  return (
    <div className="app-shell">
      <Sidebar active={view} setActive={setView} />
      <main className="app-main">
        {/* Top HUD Engineering Bar */}
        <header className="topbar">
          <div className="topbar-core-indicator">
            <div className="core-chip">
              <span className="status-dot" style={{ width: 6, height: 6 }} />
              <span>DIRECT IN-PROCESS PIPELINE</span>
            </div>
            <Clock />
          </div>

          <div className="topbar-stats-group">
            <div className="topbar-stat">
              <span>MONITORED:</span>
              <strong>{store.nodes.size || 18}</strong>
            </div>

            <div className="topbar-stat">
              <span>ACTIVE THREATS:</span>
              <strong style={{ color: store.openCount > 0 ? "var(--redl)" : "var(--teall)" }}>
                {store.openCount}
              </strong>
            </div>

            <div className="topbar-stat">
              <span>eBPF IDS:</span>
              <strong style={{ color: "var(--teall)" }}>ARMED</strong>
            </div>

            <button
              id="btn-open-install-modal"
              className="topbar-action-btn"
              onClick={() => setShowInstallModal(true)}
              title="Native Windows & Linux Binary Setup (No Web Server Required)"
            >
              <span>⚡</span>
              <span>NATIVE DEPLOYMENT</span>
            </button>
          </div>
        </header>

        {/* Global Anomaly Alert Banner */}
        <AnomalyBanner />

        {/* Standalone Native Install Modal */}
        {showInstallModal && <InstallModal onClose={() => setShowInstallModal(false)} />}

        {/* Active Panel View */}
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
      </main>
    </div>
  );
}

export default function App() {
  const [store, dispatch] = useReducer(processReducer, initialStore);
  return (
    <ProcessStoreContext.Provider value={{ store, dispatch }}>
      <AppShell />
    </ProcessStoreContext.Provider>
  );
}
