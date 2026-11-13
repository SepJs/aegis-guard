import { useState, useReducer, useEffect } from "react";
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
  const [t, setT] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setT(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return <span className="topbar-clock">{t.toLocaleTimeString("en-GB", { hour12: false })} UTC</span>;
}

const VIEW_TITLES: Record<View, string> = {
  processes: "Live Process Monitor",
  telemetry: "System Telemetry Stream",
  network: "Network IDS & Packet Inspector",
  sandbox: "Isolated Malware Sandbox",
  journal: "Threat Incident Journal",
  forensics: "Antivirus & Entropy Forensics",
  debug: "Suppressed Whitelist Events",
  audit: "Cryptographic Audit Chain",
  intel: "Threat Intelligence Feeds",
  canary: "Canary Honeytoken Tripwires",
  settings: "Settings & Storage",
};

function AppShell() {
  const [view, setView] = useState<View>("processes");
  const [showInstallModal, setShowInstallModal] = useState(false);
  const { store } = useProcessStore();
  useIpc();

  return (
    <div className="app-shell">
      <Sidebar active={view} setActive={setView} />
      <div className="app-main">
        <header className="topbar">
          <div className="topbar-id">
            <span>{VIEW_TITLES[view]}</span>
            <span style={{ color: "var(--tx3)" }}>·</span>
            <Clock />
          </div>

          <div className="tb-stat">
            Procs <span>{store.nodes.size}</span>
          </div>

          {store.systemMetrics && (
            <>
              <div className="tb-stat">
                CPU{" "}
                <span style={{ color: store.systemMetrics.cpu_pct >= 80 ? "var(--redl)" : "var(--teall)" }}>
                  {store.systemMetrics.cpu_pct.toFixed(1)}%
                </span>
              </div>
              <div className="tb-stat">
                RAM{" "}
                <span style={{ color: store.systemMetrics.mem_pct >= 85 ? "var(--amberl)" : "var(--vl)" }}>
                  {store.systemMetrics.mem_used_mb} MB ({store.systemMetrics.mem_pct.toFixed(0)}%)
                </span>
              </div>
            </>
          )}

          <div className="tb-stat">
            Threats <span style={{ color: store.openCount > 0 ? "var(--redl)" : "var(--teall)" }}>{store.openCount}</span>
          </div>

          <div
            className="tb-stat"
            style={{
              borderColor: store.ipcConnected ? "rgba(13,148,136,0.45)" : "rgba(217,119,6,0.45)",
            }}
          >
            Kernel{" "}
            <span style={{ color: store.ipcConnected ? "var(--teall)" : "var(--amberl)" }}>
              {store.ipcConnected ? (store.ipcTransport === "tauri" ? "Native IPC" : "Live /proc") : "Connecting"}
            </span>
          </div>

          <button
            id="btn-open-install-modal"
            type="button"
            className="sm-btn"
            onClick={() => setShowInstallModal(true)}
            style={{
              background: "rgba(13,148,136,0.14)",
              color: "var(--teall)",
              borderColor: "var(--teal)",
              fontWeight: 600,
            }}
          >
            Install CLI / Desktop
          </button>
        </header>

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
  return (
    <ProcessStoreContext.Provider value={{ store, dispatch }}>
      <AppShell />
    </ProcessStoreContext.Provider>
  );
}
