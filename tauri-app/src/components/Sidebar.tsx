import type { Dispatch, SetStateAction } from "react";
import { useProcessStore } from "../store/processStore";
import UpdateBanner from "./UpdateBanner";

export type View = "processes" | "telemetry" | "network" | "sandbox" | "journal" | "forensics" | "debug" | "audit" | "intel" | "canary" | "settings";

const NAV: { id: View; icon: string; label: string }[] = [
  { id: "processes", icon: "⬡", label: "PROCESSES" },
  { id: "telemetry", icon: "☵", label: "INTERNAL MOVEMENTS" },
  { id: "network", icon: "⎔", label: "NETWORK & IDS" },
  { id: "sandbox", icon: "⌬", label: "VIRUS LAB & SANDBOX" },
  { id: "journal", icon: "◈", label: "JOURNAL2" },
  { id: "forensics", icon: "⊕", label: "FORENSICS & AV" },
  { id: "debug", icon: "⊘", label: "SUPPRESSED LOG" },
  { id: "audit", icon: "⬟", label: "AUDIT LOG" },
  { id: "intel", icon: "◉", label: "THREAT INTEL" },
  { id: "canary", icon: "⟡", label: "CANARY" },
  { id: "settings", icon: "⚙", label: "SETTINGS & THEMES" },
];


export default function Sidebar({ active, setActive }: { active: View; setActive: Dispatch<SetStateAction<View>> }) {
  const { store } = useProcessStore();
  const connected = store.nodes.size > 0;

  return (
    <nav className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-hex" />
        <div className="brand-name">AEGIS-GUARD</div>
        <div className="brand-sub">ENDPOINT SECURITY SUITE</div>
        <div className="brand-author">BY VLADIMIR UNKNOWN</div>
      </div>

      <ul className="sidebar-nav">
        {NAV.map(({ id, icon, label }) => (
          <li key={id}>
            <div className={`nav-item ${active === id ? "nav-item--active" : ""}`} onClick={() => setActive(id)}>
              <span className="nav-icon">{icon}</span>
              <span className="nav-label">{label}</span>
              {id === "journal" && store.openCount > 0 && <span className="nav-badge">{store.openCount}</span>}
            </div>
          </li>
        ))}
      </ul>

      <div className="sidebar-footer">
        <div className={`engine-status ${connected ? "status--live" : "status--wait"}`}>
          <span className="status-dot" />
          <span className="status-label">{connected ? `ENGINE LIVE · ${store.nodes.size} PROCS` : "WAITING FOR ENGINE…"}</span>
        </div>
        <div className="phase-tag">FULL STACK · LINUX</div>
        <UpdateBanner />
      </div>
    </nav>
  );
}
