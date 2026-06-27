import { useState, useReducer } from "react";
import Sidebar,     { View }    from "./components/Sidebar";
import ProcessList               from "./components/ProcessList";
import ThreatJournal             from "./components/ThreatJournal";
import ForensicsPanel            from "./components/ForensicsPanel";
import DebugLogPanel             from "./components/DebugLogPanel";
import AnomalyBanner             from "./components/AnomalyBanner";
import {
  ProcessStoreContext,
  processReducer,
  initialStore,
  useProcessStore,
} from "./store/processStore";
import { useIpc } from "./hooks/useIpc";

function Clock() {
  const [time, setTime] = useState(new Date());
  useState(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  });
  return <>{time.toLocaleTimeString("en-GB", { hour12: false })} UTC</>;
}

// Inner shell — must live inside ProcessStoreContext.Provider
function AppShell() {
  const [view, setView] = useState<View>("processes");
  const { store }       = useProcessStore();
  useIpc();

  return (
    <div className="app-shell">
      <Sidebar active={view} setActive={setView} />

      <div className="app-main">
        {/* Top bar */}
        <div className="topbar">
          <span className="topbar-id">
            AEGIS-GUARD // VLADIMIR UNKNOWN // <Clock />
          </span>
          <div className="tb-stat">
            PROCS <span>{store.nodes.size}</span>
          </div>
          <div className="tb-stat">
            THREATS{" "}
            <span style={{ color: "var(--redl)" }}>{store.openCount}</span>
          </div>
          <div className="tb-stat">
            RULES <span style={{ color: "var(--vl)" }}>PAR+PATH+ARG+ENV</span>
          </div>
        </div>

        {/* Floating anomaly banners — fixed top-right */}
        <AnomalyBanner />

        {/* Main panel */}
        {view === "processes" && <ProcessList />}
        {view === "journal"   && <ThreatJournal />}
        {view === "forensics" && <ForensicsPanel />}
        {view === "debug"     && <DebugLogPanel />}
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
