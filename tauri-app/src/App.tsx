import { useState, useReducer } from "react";
import Sidebar,         { View } from "./components/Sidebar";
import ProcessList                from "./components/ProcessList";
import ThreatJournal              from "./components/ThreatJournal";
import ForensicsPanel             from "./components/ForensicsPanel";
import DebugLogPanel              from "./components/DebugLogPanel";
import AuditLogPanel              from "./components/AuditLogPanel";
import ThreatIntelPanel           from "./components/ThreatIntelPanel";
import CanaryPanel                from "./components/CanaryPanel";
import AnomalyBanner              from "./components/AnomalyBanner";
import {
  ProcessStoreContext,
  processReducer,
  initialStore,
  useProcessStore,
} from "./store/processStore";
import { useIpc } from "./hooks/useIpc";

function Clock() {
  const [t, setT] = useState(new Date());
  useState(() => {
    const id = setInterval(() => setT(new Date()), 1000);
    return () => clearInterval(id);
  });
  return <>{t.toLocaleTimeString("en-GB", { hour12: false })} UTC</>;
}

function AppShell() {
  const [view, setView] = useState<View>("processes");
  const { store }       = useProcessStore();
  useIpc();

  return (
    <div className="app-shell">
      <Sidebar active={view} setActive={setView} />

      <div className="app-main">
        <div className="topbar">
          <span className="topbar-id">
            AEGIS-GUARD // VLADIMIR UNKNOWN // <Clock />
          </span>
          <div className="tb-stat">PROCS <span>{store.nodes.size}</span></div>
          <div className="tb-stat">
            THREATS <span style={{ color: "var(--redl)" }}>{store.openCount}</span>
          </div>
          <div className="tb-stat">
            PHASE <span style={{ color: "var(--vl)" }}>5 · FULL STACK</span>
          </div>
        </div>

        <AnomalyBanner />

        {view === "processes" && <ProcessList />}
        {view === "journal"   && <ThreatJournal />}
        {view === "forensics" && <ForensicsPanel />}
        {view === "debug"     && <DebugLogPanel />}
        {view === "audit"     && <AuditLogPanel />}
        {view === "intel"     && <ThreatIntelPanel />}
        {view === "canary"    && <CanaryPanel />}
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
