import type { Dispatch, SetStateAction } from "react";
import { useProcessStore } from "../store/processStore";
import UpdateBanner from "./UpdateBanner";

export type View =
  | "processes"
  | "telemetry"
  | "network"
  | "sandbox"
  | "journal"
  | "forensics"
  | "debug"
  | "audit"
  | "intel"
  | "canary"
  | "settings";

const NAV: { id: View; icon: string; label: string }[] = [
  { id: "processes", icon: "⬡", label: "Processes" },
  { id: "telemetry", icon: "☵", label: "System Telemetry" },
  { id: "network", icon: "⎔", label: "Network & IDS" },
  { id: "forensics", icon: "⊕", label: "Antivirus & Forensics" },
  { id: "sandbox", icon: "⌬", label: "Sandbox Lab" },
  { id: "journal", icon: "◈", label: "Threat Journal" },
  { id: "intel", icon: "◉", label: "Threat Intel" },
  { id: "canary", icon: "⟡", label: "Canary Tripwires" },
  { id: "audit", icon: "⬟", label: "Audit Chain" },
  { id: "debug", icon: "⊘", label: "Suppressed Events" },
  { id: "settings", icon: "⚙", label: "Settings" },
];

export default function Sidebar({
  active,
  setActive,
}: {
  active: View;
  setActive: Dispatch<SetStateAction<View>>;
}) {
  const { store } = useProcessStore();
  const connected = store.ipcConnected || store.nodes.size > 0;

  return (
    <nav className="sidebar" aria-label="Primary navigation">
      <div className="sidebar-brand">
        <div className="brand-row">
          <div className="brand-hex" aria-hidden="true">
            <span style={{ color: "#fff", fontSize: 13, fontWeight: 700, fontFamily: "var(--mono)" }}>A</span>
          </div>
          <div>
            <div className="brand-name">AEGIS-GUARD</div>
            <div className="brand-sub">v1.2.0 · Endpoint IDS</div>
          </div>
        </div>
        <div className="brand-author">Engine 4.6.0 · Linux /proc</div>
      </div>

      <ul className="sidebar-nav">
        {NAV.map(({ id, icon, label }) => (
          <li key={id}>
            <button
              type="button"
              className={`nav-item ${active === id ? "nav-item--active" : ""}`}
              onClick={() => setActive(id)}
              aria-current={active === id ? "page" : undefined}
            >
              <span className="nav-icon" aria-hidden="true">
                {icon}
              </span>
              <span className="nav-label">{label}</span>
              {id === "journal" && store.openCount > 0 && (
                <span className="nav-badge">{store.openCount}</span>
              )}
            </button>
          </li>
        ))}
      </ul>

      <div className="sidebar-footer">
        <div className={`engine-status ${connected ? "status--live" : "status--wait"}`}>
          <span className="status-dot" />
          <span className="status-label">
            {connected ? `Engine Live · ${store.nodes.size} procs` : "Connecting engine…"}
          </span>
        </div>
        <div className="phase-tag">v1.2.0 · Engine 4.6.0</div>
        <UpdateBanner />
      </div>
    </nav>
  );
}
